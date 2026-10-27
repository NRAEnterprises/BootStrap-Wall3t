import unittest
from bootstrap_wall3t.vault.pqc_key_vault import PQCKeyVault

class TestPQCVault(unittest.TestCase):
    def setUp(self):
        self.vault = PQCKeyVault(ledger_path="./data/test_vault/pqc_ledger.enc")

    def tearDown(self):
        self.vault.wipe_session()
        if self.vault.ledger_path.exists():
            self.vault.ledger_path.unlink()

    def test_pqc_ceremony_roundtrip(self):
        priv_kem, pub_kem = self.vault.generate_session_keypair()
        priv_dsa, pub_dsa = self.vault.generate_agent_identity()

        sample_ledger = {
            "agent_007": {
                "evm_key": "0xdeadbeef",
                "fuel_key": "fuel_priv_key_001"
            }
        }

        # 1. Encrypt and save
        self.vault.save_encrypted_ledger(sample_ledger, pub_kem)
        self.assertTrue(self.vault.ledger_path.exists())

        # 2. Unlock ceremony
        self.vault.unlock_session(priv_kem)
        self.assertTrue(self.vault.is_unlocked())

        # 3. Retrieve keys
        keys = self.vault.get_agent_keys("agent_007")
        self.assertEqual(keys["evm_key"], "0xdeadbeef")
        self.assertEqual(keys["fuel_key"], "fuel_priv_key_001")

        # 4. Wipe
        self.vault.wipe_session()
        self.assertFalse(self.vault.is_unlocked())
        with self.assertRaises(PermissionError):
            self.vault.get_agent_keys("agent_007")

if __name__ == "__main__":
    unittest.main()
