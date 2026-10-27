import unittest
from pathlib import Path
from bootstrap_wall3t.vault.pqc_key_vault import PQCKeyVault
from bootstrap_wall3t.wallet.agent_wallet import AgentWallet
from bootstrap_wall3t.wallet.blacklisting import ThreatRegistry, ThreatQuarantineException
from bootstrap_wall3t.wallet.routes import routes
from bootstrap_wall3t.bootstrap.arbitrage_scout import FlashArbitrageScout

class TestRoutesAndWallet(unittest.TestCase):
    def setUp(self):
        self.vault = PQCKeyVault(ledger_path="./data/test_wallet_pqc.enc")
        self.priv_kem, self.pub_kem = self.vault.generate_session_keypair()
        self.vault.save_encrypted_ledger({
            "agent_alpha": {
                "fuel_privkey": "fuel_alpha_key",
                "arbitrum_privkey": "arb_alpha_key"
            }
        }, self.pub_kem)
        self.vault.unlock_session(self.priv_kem)
        
        self.test_shield_path = Path("./data/test_wallet_shield.json")
        self.shield = ThreatRegistry(registry_path=str(self.test_shield_path))
        self.wallet = AgentWallet("agent_alpha", self.vault, self.shield)

    def tearDown(self):
        self.vault.wipe_session()
        if self.vault.ledger_path.exists():
            self.vault.ledger_path.unlink()
        if self.test_shield_path.exists():
            self.test_shield_path.unlink()

    def test_routing_matrix_fuel_and_lightning(self):
        # Bitcoin transfer -> must recommend Lightning
        btc_plan = routes.plan_route("lnd", "lnd", "BTC", 50.0)
        self.assertIn("LIGHTNING", btc_plan.guideline)
        self.assertLess(btc_plan.total_estimated_fee_usd, 0.01)

        # Micro-swap -> must route via Fuel Network
        swap_plan = routes.plan_route("arbitrum", "fuel", "USDC", 20.0)
        self.assertIn("FUEL", swap_plan.guideline)
        self.assertEqual(swap_plan.hops[0].chain, "fuel")

    def test_wallet_trade_and_quarantine(self):
        # 1. Normal safe trade succeeds
        res = self.wallet.execute_swap("fuel", "fuel", "0xETH", "0xUSDC", 1.0, 2500.0)
        self.assertEqual(res["status"], "COMPLETED")

        # 2. Flag bad token
        self.wallet.flag_suspicious_token("fuel", "0xPOISON", "POISON", "Reverts on transfer")

        # 3. Swap to bad token is strictly blocked by AgentShield
        with self.assertRaises(ThreatQuarantineException):
            self.wallet.execute_swap("fuel", "fuel", "0xETH", "0xPOISON", 1.0, 50.0)

    def test_flash_loan_arbitrage_scout(self):
        scout = FlashArbitrageScout()
        res = scout.scan_spread(
            token_pair="ETH/USDC",
            buy_dex="Uniswap-v3",
            sell_dex="Camelot",
            price_buy=2500.0,
            price_sell=2525.0, # 1% spread
            borrow_amount_usd=10000.0,
            chain="arbitrum"
        )
        self.assertTrue(res["profitable"])
        self.assertGreater(res["net_profit_usd"], 50.0)
        self.assertEqual(res["provider"], "Balancer V2 Vault (0% Flash Loan Fee)")

if __name__ == "__main__":
    unittest.main()
