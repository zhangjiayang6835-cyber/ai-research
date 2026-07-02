"""
Uniswap V3 TWAP Oracle Implementation - SECURE VERSION
Fixes flash swap manipulation by using time-weighted average
with proper observation cardinality and minimum duration checks.
"""
from typing import Tuple, Optional, List
from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN
import time
class Observation:
    timestamp: int
    tick_cumulative: int
    block_number: int
    liquidity: int
    initialized: bool


@dataclass
    token1: str
    observations: list
    observation_index: int
    observation_cardinality: int
    observation_cardinality_next: int
    min_observation_duration: int = 300  # Minimum 5 minutes for TWAP


class UniswapV3TWAPOracle:
        self.pools: dict[str, Pool] = {}
        self.price_cache: dict[str, Tuple[Decimal, int]] = {}
        self.max_twap_window = 3600  # 1 hour max
        self.min_observation_duration = 300  # 5 minutes minimum
        self.min_observation_cardinality = 2  # At least 2 observations
        self.max_price_deviation = Decimal("0.10")  # 10% max deviation check
        self.last_valid_prices: dict[str, Decimal] = {}
    
    def add_pool(self, pool_address: str, token0: str, token1: str) -> None:
        if pool_address not in self.pools:
                address=pool_address,
                token0=token0,
                token1=token1,
                observations=[Observation(0, 0, 0, 0, False)] * 65535,
                observation_index=0,
                observation_cardinality=1,
                observation_cardinality_next=1,
                observation_index=0
            )
    
        if pool_address not in self.pools:
            raise ValueError(f"Pool {pool_address} not found")
        
        pool = self.pools[pool_address]
        
        # SECURE: Update observation with cardinality management
        current_index = pool.observation_index % 65535
        next_index = (current_index + 1) % 65535
        
        # Write new observation
        pool.observations[current_index] = Observation(
            timestamp=timestamp,
            tick_cumulative=tick_cumulative,
            block_number=block_number,
            liquidity=liquidity,
            initialized=True
        )
        
        # Update cardinality tracking
        if next_index >= pool.observation_cardinality: