'''Registry of chain providers used by the wallet API.

The registry is a simple dict that maps a lower‑case chain identifier to an
instance of the corresponding ``ChainProvider`` subclass.  Adding a new chain is
as easy as importing the provider class and inserting it into ``PROVIDERS``.
'''

from typing import Dict

from .base import ChainProvider
from .bitcoin import BitcoinProvider
from .evm import EVMProvider  # handles Ethereum, Arbitrum, Base, etc.
from .solana import SolanaProvider
from .fuel import FuelProvider

# Keys are the URL path segment used in the API (e.g. /tx/bitcoin/...) 
PROVIDERS: Dict[str, ChainProvider] = {
    "bitcoin": BitcoinProvider(),
    "ethereum": EVMProvider(chain="ethereum"),
    "arbitrum": EVMProvider(chain="arbitrum"),
    "base": EVMProvider(chain="base"),
    "solana": SolanaProvider(),
    "fuel": FuelProvider(),
    "polygon": EVMProvider(chain="polygon"),
}

def get_provider(chain_id: str) -> ChainProvider:
    """Lookup a provider by its identifier.

    Raises `KeyError` if the chain is not registered.
    """
    return PROVIDERS[chain_id.lower()]
