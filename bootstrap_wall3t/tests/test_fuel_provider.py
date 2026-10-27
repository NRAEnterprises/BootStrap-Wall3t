# Tests for the Fuel provider implementation and registry integration

import pytest

# Import the provider class and registry helper
from bootstrap_wall3t.chain.fuel import FuelProvider
from bootstrap_wall3t.chain.registry import get_provider, PROVIDERS


def test_fuel_provider_basic_methods():
    """Ensure the placeholder methods return sensible defaults."""
    provider = FuelProvider()
    # derive_key should return a deterministic dummy key for testing
    key = provider.derive_key("test-mnemonic")
    assert isinstance(key, str)
    assert key.startswith("fuel-key-")

    # get_address uses the derived key; should return a dummy address string
    address = provider.get_address(key)
    assert isinstance(address, str)
    assert address.startswith("fuel1")

    # build_tx creates a simple dictionary representing a transaction
    tx = provider.build_tx(
        sender=address,
        to="fuel1receiver",
        amount=12345,
        fee=10,
        nonce=0,
    )
    assert isinstance(tx, dict)
    for field in ["sender", "to", "amount", "fee", "nonce"]:
        assert field in tx
    assert tx["sender"] == address
    assert tx["to"] == "fuel1receiver"
    assert tx["amount"] == 12345

    # broadcast_tx should return a dummy transaction hash string
    tx_hash = provider.broadcast_tx(tx)
    assert isinstance(tx_hash, str)
    assert tx_hash.startswith("0x")


def test_registry_contains_fuel_provider():
    """The global registry should expose the FuelProvider under the 'fuel' key."""
    assert "fuel" in PROVIDERS
    fuel = get_provider("fuel")
    assert isinstance(fuel, FuelProvider)

    # Verify that the provider from the registry behaves like the class directly
    assert fuel.get_address(fuel.derive_key("mnemonic")) == fuel.get_address(
        fuel.derive_key("mnemonic")
    )


def test_registry_unknown_key_raises():
    """Requesting an unknown chain should raise a KeyError."""
    with pytest.raises(KeyError):
        get_provider("nonexistent-chain")
