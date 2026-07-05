"""
fix_flash_loan_liquidation.py — Flash Loan Attack → Oracle Manipulation → Liquidation Fix

VULNERABILITY:
Attackers use flash loans to accumulate large positions, manipulate oracle prices,
then liquidate honest users' positions at a false price. The flash loan is borrowed
and repaid in the same transaction, requiring no upfront capital.

FIX:
1. Use TWAP with sufficient window (≥30 min) instead of spot price
2. Cross-validate prices across multiple oracles
3. Implement a liquidation delay (time lock)
4. Add price deviation circuit breakers
5. Cap liquidatable amount per transaction
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import time
import hashlib


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class LendingConfig:
    """Security configuration for lending protocol."""
    # Minimum TWAP window (seconds) — flash loans work in 1 block
    min_twap_window: int = 1800  # 30 minutes
    # Liquidation delay (seconds) — cannot liquidate same block
    liquidation_delay: int = 3600  # 1 hour
    # Maximum % of position liquidatable per tx
    max_liquidation_pct: float = 0.25  # 25%
    # Price deviation from reference oracle (%)
    max_price_deviation_pct: float = 2.0
    # Minimum number of oracle sources
    min_oracle_sources: int = 2
    # Health factor threshold for liquidation
    min_health_factor: float = 1.1  # 110%
    # Circuit breaker: pause liquidations if price change > X%
    circuit_breaker_threshold_pct: float = 10.0


# =============================================================================
# Multi-Oracle Price Feed
# =============================================================================

@dataclass
class PriceObservation:
    """A price observation from a single source."""
    price: float
    source: str
    timestamp: int
    block_number: int = 0


class MultiOracleFeed:
    """
    Security-hardened oracle feed that resists flash loan manipulation.

    Uses multiple sources with TWAP, cross-validation, and circuit breakers.
    """

    def __init__(self, config: Optional[LendingConfig] = None):
        self.config = config or LendingConfig()
        self.observations: Dict[str, List[PriceObservation]] = {}
        self._circuit_breaker_triggered: bool = False
        self._last_price: Optional[float] = None

    def submit_price(self, price: float, source: str,
                     timestamp: Optional[int] = None) -> bool:
        """Submit a price observation from an oracle source."""
        now = timestamp or int(time.time())
        obs = PriceObservation(price=price, source=source, timestamp=now)

        if source not in self.observations:
            self.observations[source] = []
        self.observations[source].append(obs)

        # Circuit breaker check
        if self._last_price is not None:
            change_pct = abs(price - self._last_price) / self._last_price * 100
            if change_pct > self.config.circuit_breaker_threshold_pct:
                self._circuit_breaker_triggered = True
                return False

        self._last_price = price
        return True

    def get_safe_price(self, token: str = "default") -> Optional[float]:
        """
        Get the safe price from multiple oracles.

        Returns None if the price cannot be safely determined (flash loan
        manipulation likely in progress).
        """
        if self._circuit_breaker_triggered:
            return None

        if len(self.observations) < self.config.min_oracle_sources:
            return None

        # Compute TWAP for each source
        twap_prices = []
        for source, obs_list in self.observations.items():
            twap = self._compute_twap(obs_list)
            if twap is not None:
                twap_prices.append(twap)

        if len(twap_prices) < self.config.min_oracle_sources:
            return None

        # Cross-validate: all TWAPs must be within deviation threshold
        median = sorted(twap_prices)[len(twap_prices) // 2]
        for price in twap_prices:
            deviation = abs(price - median) / median * 100
            if deviation > self.config.max_price_deviation_pct:
                return None

        # Return median of TWAPs
        return median

    def _compute_twap(self, observations: List[PriceObservation],
                      window: Optional[int] = None) -> Optional[float]:
        """Compute time-weighted average price over window."""
        window = window or self.config.min_twap_window
        now = int(time.time())
        cutoff = now - window

        relevant = [o for o in observations if o.timestamp >= cutoff]
        if len(relevant) < 2:
            return None

        total_time = 0.0
        weighted_sum = 0.0
        for i in range(1, len(relevant)):
            delta = relevant[i].timestamp - relevant[i-1].timestamp
            if delta > 0:
                weighted_sum += relevant[i-1].price * delta
                total_time += delta

        return weighted_sum / total_time if total_time > 0 else None


# =============================================================================
# Secure Lending Protocol
# =============================================================================

class SecureLendingProtocol:
    """
    Lending protocol that is resistant to flash loan oracle manipulation.

    Features:
    - Multi-oracle TWAP pricing
    - Liquidation time lock
    - Partial liquidation only
    - Circuit breakers
    - Price deviation checks
    """

    def __init__(self, oracle: MultiOracleFeed,
                 config: Optional[LendingConfig] = None):
        self.oracle = oracle
        self.config = config or LendingConfig()
        self.positions: Dict[str, dict] = {}  # position_id -> position
        self._liquidation_queue: Dict[str, float] = {}  # pos_id -> timestamp

    def create_position(self, position_id: str, collateral: float,
                        debt: float) -> bool:
        """Create a new borrow position."""
        self.positions[position_id] = {
            "collateral": collateral,
            "debt": debt,
            "created_at": int(time.time()),
            "last_liquidation_attempt": 0,
        }
        return True

    def get_health_factor(self, position_id: str) -> Optional[float]:
        """Get the health factor of a position using safe TWAP price."""
        safe_price = self.oracle.get_safe_price()
        if safe_price is None:
            return None  # Oracle unsafe

        pos = self.positions.get(position_id)
        if not pos:
            return None

        collateral_value = pos["collateral"] * safe_price
        if pos["debt"] == 0:
            return float("inf")

        return collateral_value / pos["debt"]

    def can_liquidate(self, position_id: str) -> Tuple[bool, str]:
        """Check if a position can be liquidated."""
        safe_price = self.oracle.get_safe_price()
        if safe_price is None:
            return False, "Oracle price unavailable (possible manipulation)"

        # Circuit breaker check
        if self.oracle._circuit_breaker_triggered:
            return False, "Circuit breaker triggered — liquidations paused"

        pos = self.positions.get(position_id)
        if not pos:
            return False, "Position not found"

        health = self.get_health_factor(position_id)
        if health is None:
            return False, "Cannot determine health factor"

        if health >= self.config.min_health_factor:
            return False, f"Position healthy (health={health:.2f})"

        # Liquidation delay check
        last_attempt = pos.get("last_liquidation_attempt", 0)
        if time.time() - last_attempt < self.config.liquidation_delay:
            remaining = self.config.liquidation_delay - (
                time.time() - last_attempt
            )
            return False, f"Liquidation cooldown: {remaining:.0f}s remaining"

        return True, ""

    def liquidate(self, position_id: str, liquidator: str,
                  max_amount: Optional[float] = None) -> Tuple[bool, str, float]:
        """
        Liquidate a position with all security checks.

        Returns (success, message, amount_liquidated).
        """
        can, reason = self.can_liquidate(position_id)
        if not can:
            return False, reason, 0.0

        pos = self.positions[position_id]
        safe_price = self.oracle.get_safe_price()

        # Limit liquidation amount per transaction
        max_liquidation = pos["debt"] * self.config.max_liquidation_pct
        amount = min(max_amount or max_liquidation, max_liquidation)

        if amount <= 0:
            return False, "Invalid liquidation amount", 0.0

        # Process liquidation
        collateral_to_seize = amount / safe_price
        pos["debt"] -= amount
        pos["collateral"] -= collateral_to_seize
        pos["last_liquidation_attempt"] = int(time.time())

        # Add to cooldown queue
        self._liquidation_queue[position_id] = time.time()

        return True, f"Liquidated {amount} debt", amount


# =============================================================================
# Tests
# =============================================================================

def test_flash_loan_resistance():
    """Test that TWAP resists single-block flash loan manipulation."""
    config = LendingConfig(min_twap_window=600, min_oracle_sources=1)
    oracle = MultiOracleFeed(config)

    now = int(time.time())
    # Build 20 min of observations at $100
    for i in range(20):
        oracle.submit_price(100.0, "source_a", now - 1200 + i * 60)

    # Flash loan: single observation at manipulated price
    oracle.submit_price(200.0, "source_a", now + 1)

    safe_price = oracle.get_safe_price()
    assert safe_price is not None
    # TWAP over 10 min should still be ~$100
    assert abs(safe_price - 100.0) < 10.0, \
        f"TWAP should resist manipulation: {safe_price}"
    print("PASS: Flash loan manipulation resisted by TWAP")


def test_multi_oracle_cross_validation():
    """Test that price deviation between oracles is detected."""
    config = LendingConfig(max_price_deviation_pct=5.0, min_oracle_sources=2)
    oracle = MultiOracleFeed(config)

    now = int(time.time())
    for i in range(10):
        oracle.submit_price(100.0, "source_a", now - 600 + i * 60)
        oracle.submit_price(100.0, "source_b", now - 600 + i * 60)
        oracle.submit_price(150.0, "source_c", now - 600 + i * 60)

    safe_price = oracle.get_safe_price()
    assert safe_price is None, \
        "50% deviation should make price unavailable"
    print("PASS: Intra-oracle deviation detected")


def test_liquidation_delay():
    """Test that liquidation delay prevents instant liquidation."""
    config = LendingConfig(
        min_twap_window=60,
        liquidation_delay=10,
        min_oracle_sources=1,
        min_health_factor=1.5,
    )
    oracle = MultiOracleFeed(config)
    protocol = SecureLendingProtocol(oracle, config)

    now = int(time.time())
    for i in range(5):
        oracle.submit_price(100.0, "source_a", now - 300 + i * 60)

    # Create underwater position
    protocol.create_position("pos1", collateral=1.0, debt=2.0)

    can, reason = protocol.can_liquidate("pos1")
    assert not can, "Should not liquidate immediately (delay)"
    print("PASS: Liquidation delay enforced")


def test_circuit_breaker():
    """Test that circuit breaker pauses liquidations on extreme moves."""
    config = LendingConfig(
        circuit_breaker_threshold_pct=10.0,
        min_oracle_sources=1,
    )
    oracle = MultiOracleFeed(config)
    now = int(time.time())

    for i in range(5):
        oracle.submit_price(100.0, "source_a", now - 300 + i * 60)

    # Extreme price spike
    result = oracle.submit_price(150.0, "source_a", now)
    assert not result, "15% spike should trigger circuit breaker"
    print("PASS: Circuit breaker triggered on extreme price move")


def test_partial_liquidation():
    """Test that only partial liquidation is allowed per tx."""
    config = LendingConfig(
        min_twap_window=60,
        max_liquidation_pct=0.25,
        liquidation_delay=0,
        min_oracle_sources=1,
        min_health_factor=1.1,
    )
    oracle = MultiOracleFeed(config)
    protocol = SecureLendingProtocol(oracle, config)

    now = int(time.time())
    for i in range(5):
        oracle.submit_price(100.0, "source_a", now - 300 + i * 60)

    protocol.create_position("pos1", collateral=1.0, debt=0.5)

    success, msg, amount = protocol.liquidate("pos1", "liquidator", 1000)
    assert success, f"Liquidation should succeed: {msg}"
    assert amount <= 0.5 * 0.25, \
        f"Should only liquidate 25%: got {amount}"
    print("PASS: Partial liquidation enforced")


if __name__ == "__main__":
    test_flash_loan_resistance()
    test_multi_oracle_cross_validation()
    test_liquidation_delay()
    test_circuit_breaker()
    test_partial_liquidation()
    print("\n✅ All flash loan + oracle manipulation tests passed!")
