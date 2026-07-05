"""
fix_oracle_manipulation.py — Uniswap V3 TWAP Oracle Manipulation via Flash Swap Fix

VULNERABILITY:
Attackers can manipulate Uniswap V3 TWAP oracles using flash swaps to create
artificial price movements within a single block, then exploit protocols that
rely on the manipulated TWAP for liquidations, margin calls, or asset pricing.

FIX:
1. Use a TWAP with sufficient time window (≥30 min, not 1-block)
2. Validate TWAP against a secondary oracle (Chainlink) before acting on it
3. Add price deviation bounds check
4. Implement circuit breaker for rapid price changes
5. Require minimum observations before using oracle data
"""

import hashlib
import hmac
import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class OracleConfig:
    """Safe oracle configuration — resists flash loan manipulation."""
    # Minimum TWAP window in seconds (≥1800 = 30 min resists flash loans)
    min_twap_window_seconds: int = 1800
    # Maximum allowed price deviation from Chainlink (%)
    max_chainlink_deviation_pct: float = 2.0
    # Minimum observations required before trusting TWAP
    min_observations: int = 10
    # Circuit breaker: max price change in one update (%)
    max_single_update_pct: float = 5.0
    # Cooldown between price updates (seconds)
    update_cooldown_seconds: int = 15


# =============================================================================
# Safe TWAP Oracle
# =============================================================================

@dataclass
class Observation:
    """A single price observation with timestamp."""
    price: float
    timestamp: int
    cumulative_sum: float


class TWAPOracle:
    """
    Manipulation-resistant TWAP oracle.

    Maintains a sliding window of observations. Computes the time-weighted
    average price over the window, which cannot be manipulated by a single
    block's flash swap because the window spans many blocks.
    """

    def __init__(self, config: Optional[OracleConfig] = None,
                 chainlink_fallback: Optional[float] = None):
        self.config = config or OracleConfig()
        self.observations: deque = deque(maxlen=1000)
        self.last_update_time: int = 0
        self.chainlink_price: Optional[float] = chainlink_fallback
        self.chainlink_update_time: int = 0

    def submit_observation(self, price: float, timestamp: Optional[int] = None) -> bool:
        """Submit a price observation with rate limiting."""
        now = timestamp or int(time.time())

        # Rate limit — prevents spam
        if now - self.last_update_time < self.config.update_cooldown_seconds:
            return False

        # Check single-update deviation
        if self.observations:
            last_price = self.observations[-1].price
            deviation = abs(price - last_price) / last_price * 100
            if deviation > self.config.max_single_update_pct:
                # Log suspicious price (circuit breaker)
                _log_alert(
                    f"PRICE SPIKED: {deviation:.2f}% change "
                    f"({last_price} -> {price})"
                )
                return False

        self.observations.append(Observation(
            price=price,
            timestamp=now,
            cumulative_sum=self._compute_cumulative(price, now)
        ))
        self.last_update_time = now
        return True

    def get_twap(self, window_seconds: Optional[int] = None) -> Optional[float]:
        """
        Get the time-weighted average price over the given window.

        Uses a minimum window of `min_twap_window_seconds` to resist
        single-block flash loan manipulation.
        """
        window = max(window_seconds or self.config.min_twap_window_seconds,
                     self.config.min_twap_window_seconds)

        if len(self.observations) < self.config.min_observations:
            return None  # Not enough data yet

        now = int(time.time())
        cutoff = now - window

        # Find observations within window
        relevant = [o for o in self.observations if o.timestamp >= cutoff]
        if len(relevant) < 2:
            return None

        # Time-weighted average
        total_time = 0.0
        weighted_sum = 0.0
        for i in range(1, len(relevant)):
            time_delta = relevant[i].timestamp - relevant[i - 1].timestamp
            if time_delta > 0:
                weighted_sum += relevant[i - 1].price * time_delta
                total_time += time_delta

        if total_time == 0:
            return None

        return weighted_sum / total_time

    def validate_with_chainlink(self, twap_price: float) -> bool:
        """
        Cross-validate TWAP against Chainlink oracle.

        Returns False if deviation exceeds threshold, indicating possible
        TWAP manipulation.
        """
        if self.chainlink_price is None:
            return True  # No Chainlink reference — skip validation

        deviation = abs(twap_price - self.chainlink_price) / self.chainlink_price * 100
        if deviation > self.config.max_chainlink_deviation_pct:
            _log_alert(
                f"ORACLE DEVIATION: TWAP={twap_price} vs "
                f"Chainlink={self.chainlink_price} "
                f"({deviation:.2f}%)"
            )
            return False
        return True

    def get_safe_price(self) -> Optional[float]:
        """
        Get a price that has passed all manipulation checks.

        1. Compute TWAP over minimum window
        2. Validate against Chainlink
        3. Return None if either check fails
        """
        twap = self.get_twap()
        if twap is None:
            return None
        if not self.validate_with_chainlink(twap):
            return None
        return twap

    def update_chainlink_price(self, price: float, timestamp: Optional[int] = None):
        """Update the reference Chainlink price."""
        self.chainlink_price = price
        self.chainlink_update_time = timestamp or int(time.time())

    def _compute_cumulative(self, price: float, timestamp: int) -> float:
        """Compute cumulative sum for the observation."""
        if not self.observations:
            return price * timestamp
        prev = self.observations[-1]
        time_elapsed = timestamp - prev.timestamp
        return prev.cumulative_sum + prev.price * max(time_elapsed, 0)


# =============================================================================
# Safe DeFi Lending Protocol (uses TWAP oracle safely)
# =============================================================================

class SafeLendingProtocol:
    """
    Lending protocol that uses manipulation-resistant TWAP oracle.

    Cannot be liquidated via flash loan oracle manipulation because:
    - Uses ≥30 min TWAP (not spot price)
    - Cross-validates with Chainlink
    - Has price deviation circuit breakers
    """

    def __init__(self, oracle: TWAPOracle):
        self.oracle = oracle
        self.positions = {}  # user -> collateral_amt, debt_amt
        self.min_collateral_ratio = 1.5  # 150%

    def get_liquidation_price(self, position_id: str) -> Optional[float]:
        """
        Get the price at which a position becomes liquidatable.

        Uses safe TWAP instead of spot price.
        """
        safe_price = self.oracle.get_safe_price()
        if safe_price is None:
            return None  # Oracle unsafe — freeze liquidations

        pos = self.positions.get(position_id)
        if not pos:
            return None

        # Liquidation price = debt * min_collateral_ratio / collateral
        return pos['debt'] * self.min_collateral_ratio / pos['collateral']

    def is_liquidatable(self, position_id: str) -> bool:
        """Check if a position is liquidatable using safe TWAP."""
        safe_price = self.oracle.get_safe_price()
        if safe_price is None:
            return False  # Freeze if oracle is unreliable

        pos = self.positions.get(position_id)
        if not pos:
            return False

        collateral_value = pos['collateral'] * safe_price
        return collateral_value < pos['debt'] * self.min_collateral_ratio


# =============================================================================
# Utilities
# =============================================================================

def _log_alert(message: str):
    """Log a security alert."""
    print(f"[ALERT] {message}")


# =============================================================================
# Tests
# =============================================================================

def test_oracle_resists_flash_loan_manipulation():
    """Test that a single-block price spike doesn't affect TWAP."""
    config = OracleConfig(min_twap_window_seconds=600, min_observations=2)
    oracle = TWAPOracle(config, chainlink_fallback=100.0)

    # Build 30 min of observations at $100
    now = int(time.time())
    for i in range(30):
        oracle.submit_observation(100.0, now - 1800 + i * 60)

    # Flash loan manipulation: single observation at manipulated price
    oracle.submit_observation(200.0, now + 1)

    # TWAP should still be ~$100
    twap = oracle.get_twap(600)
    assert twap is not None, "TWAP should be available"
    assert abs(twap - 100.0) < 1.0, (
        f"TWAP should resist manipulation: got {twap}"
    )
    print("PASS: TWAP resists flash loan manipulation")


def test_single_update_circuit_breaker():
    """Test that sudden price spikes are rejected."""
    config = OracleConfig(max_single_update_pct=5.0)
    oracle = TWAPOracle(config, chainlink_fallback=100.0)

    now = int(time.time())
    oracle.submit_observation(100.0, now - 60)
    
    # 20% spike — should be rejected
    result = oracle.submit_observation(120.0, now)
    assert result is False, "20% spike should be rejected"
    print("PASS: Single-update circuit breaker works")


def test_chainlink_deviation_check():
    """Test that TWAP deviating from Chainlink is rejected."""
    oracle = TWAPOracle(chainlink_fallback=100.0)

    now = int(time.time())
    for i in range(30):
        oracle.submit_observation(150.0, now - 1800 + i * 60)

    safe_price = oracle.get_safe_price()
    assert safe_price is None, (
        "TWAP deviating 50% from Chainlink should return None"
    )
    print("PASS: Chainlink deviation check works")


def test_min_observations_required():
    """Test that oracle requires sufficient observations."""
    config = OracleConfig(min_observations=5)
    oracle = TWAPOracle(config)

    now = int(time.time())
    for i in range(3):
        oracle.submit_observation(100.0, now - 300 + i * 100)

    twap = oracle.get_twap()
    assert twap is None, "Should require min observations"
    print("PASS: Minimum observations enforced")


if __name__ == "__main__":
    test_oracle_resists_flash_loan_manipulation()
    test_single_update_circuit_breaker()
    test_chainlink_deviation_check()
    test_min_observations_required()
    print("\n✅ All oracle manipulation tests passed!")
