import unittest
from pathlib import Path
from bootstrap_wall3t.wallet.blacklisting import ThreatRegistry, ThreatQuarantineException

class TestThreatRegistry(unittest.TestCase):
    def setUp(self):
        self.test_path = Path("./data/test_threats.json")
        self.shield = ThreatRegistry(registry_path=str(self.test_path))

    def tearDown(self):
        if self.test_path.exists():
            self.test_path.unlink()

    def test_quarantine_and_interception(self):
        # 1. Quarantine malicious token
        self.shield.quarantine_asset(
            token_address="0xBADCOIN123",
            chain="arbitrum",
            symbol="RUG",
            reason="Liquidity pulled",
            reported_by="agent_scout_1"
        )

        # 2. Assert blocked
        with self.assertRaises(ThreatQuarantineException):
            self.shield.assert_trade_permitted("arbitrum", "0xBADCOIN123")

        # 3. Assert blocked by symbol
        with self.assertRaises(ThreatQuarantineException):
            self.shield.assert_trade_permitted("arbitrum", "0xOTHER", symbol="RUG")

        # 4. Safe token passes
        self.shield.assert_trade_permitted("arbitrum", "0xSAFECOIN456", symbol="SAFE")

    def test_heuristic_evaluation(self):
        # Token with 15% sell tax
        toxic_token = {
            "chain": "fuel",
            "address": "0xTOXIC",
            "symbol": "TAX15",
            "sell_tax_pct": 15.0,
            "liquidity_usd": 10000.0
        }
        res = self.shield.evaluate_token_risk(toxic_token, reported_by="agent_evaluator")
        self.assertFalse(res)

        # Confirm quarantined
        with self.assertRaises(ThreatQuarantineException):
            self.shield.assert_trade_permitted("fuel", "0xTOXIC")

if __name__ == "__main__":
    unittest.main()
