"""
Thin wrapper around web3.py for anchoring report hashes on a local
Hardhat blockchain via the AuditRegistry smart contract.

Design notes:
- Only the assessment ID, report SHA-256 hash, and a timestamp are
  ever sent to the contract. The full report content and any private
  data are NEVER written on-chain.
- If the blockchain is unreachable (e.g. Hardhat node not started) or
  no contract address is configured, anchoring fails gracefully and
  the API surfaces a clear "not anchored" / "failed" status rather
  than faking success.
"""
import os
import json
from pathlib import Path

from web3 import Web3

ARTIFACT_PATH = Path(__file__).resolve().parents[3] / "blockchain" / "artifacts" / \
    "contracts" / "AuditRegistry.sol" / "AuditRegistry.json"


def _load_abi():
    if ARTIFACT_PATH.exists():
        with open(ARTIFACT_PATH) as f:
            return json.load(f)["abi"]
    # Minimal ABI fallback in case Hardhat hasn't been compiled yet —
    # matches AuditRegistry.sol exactly, so the app can still start
    # and give a clear error rather than crashing on import.
    return json.loads("""
    [
      {"inputs":[{"internalType":"string","name":"assessmentId","type":"string"},
                 {"internalType":"string","name":"reportHash","type":"string"}],
       "name":"registerAssessment","outputs":[],"stateMutability":"nonpayable","type":"function"},
      {"inputs":[{"internalType":"string","name":"assessmentId","type":"string"}],
       "name":"getAssessment",
       "outputs":[{"internalType":"string","name":"reportHash","type":"string"},
                  {"internalType":"uint256","name":"timestamp","type":"uint256"},
                  {"internalType":"address","name":"registeredBy","type":"address"}],
       "stateMutability":"view","type":"function"},
      {"inputs":[{"internalType":"string","name":"assessmentId","type":"string"},
                 {"internalType":"string","name":"reportHash","type":"string"}],
       "name":"verifyHash","outputs":[{"internalType":"bool","name":"","type":"bool"}],
       "stateMutability":"view","type":"function"},
      {"anonymous":false,"inputs":[
          {"indexed":true,"internalType":"string","name":"assessmentId","type":"string"},
          {"indexed":false,"internalType":"string","name":"reportHash","type":"string"},
          {"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"},
          {"indexed":false,"internalType":"address","name":"registeredBy","type":"address"}],
       "name":"AssessmentRegistered","type":"event"}
    ]
    """)


class BlockchainClient:
    def __init__(self):
        self.provider_uri = os.getenv("WEB3_PROVIDER_URI", "http://127.0.0.1:8545")
        self.contract_address = os.getenv("CONTRACT_ADDRESS", "").strip()
        self.private_key = os.getenv("DEPLOYER_PRIVATE_KEY", "").strip()
        self.w3 = Web3(Web3.HTTPProvider(self.provider_uri, request_kwargs={"timeout": 5}))
        self.abi = _load_abi()

    def is_configured(self) -> bool:
        return bool(self.contract_address)

    def is_connected(self) -> bool:
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    def _contract(self):
        return self.w3.eth.contract(address=Web3.to_checksum_address(self.contract_address), abi=self.abi)

    def register_assessment(self, assessment_id: str, report_hash: str) -> dict:
        """
        Send a transaction to AuditRegistry.registerAssessment(assessmentId, reportHash).
        Returns {"success": bool, "tx_hash": str|None, "error": str|None}
        """
        if not self.is_configured():
            return {"success": False, "tx_hash": None,
                     "error": "CONTRACT_ADDRESS not configured. Deploy the contract and set it in .env."}
        if not self.is_connected():
            return {"success": False, "tx_hash": None,
                     "error": f"Cannot connect to blockchain node at {self.provider_uri}. "
                              "Start it with `npx hardhat node`."}
        if not self.private_key:
            return {"success": False, "tx_hash": None,
                     "error": "DEPLOYER_PRIVATE_KEY not configured."}

        try:
            account = self.w3.eth.account.from_key(self.private_key)
            contract = self._contract()
            nonce = self.w3.eth.get_transaction_count(account.address)

            tx = contract.functions.registerAssessment(assessment_id, report_hash).build_transaction({
                "from": account.address,
                "nonce": nonce,
                "gas": 300000,
                "gasPrice": self.w3.eth.gas_price,
            })
            signed = self.w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)

            if receipt.status != 1:
                return {"success": False, "tx_hash": tx_hash.hex(), "error": "Transaction reverted."}

            return {"success": True, "tx_hash": tx_hash.hex(), "error": None}
        except Exception as e:
            return {"success": False, "tx_hash": None, "error": str(e)}

    def get_assessment(self, assessment_id: str) -> dict:
        """Read back the on-chain record for an assessment ID."""
        if not self.is_configured() or not self.is_connected():
            return {"success": False, "error": "Blockchain not configured or unreachable."}
        try:
            contract = self._contract()
            report_hash, timestamp, registered_by = contract.functions.getAssessment(assessment_id).call()
            if not report_hash:
                return {"success": False, "error": "No on-chain record found for this assessment ID."}
            return {
                "success": True,
                "report_hash": report_hash,
                "timestamp": timestamp,
                "registered_by": registered_by,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def verify_hash(self, assessment_id: str, report_hash: str) -> dict:
        """Call the contract's verifyHash view function."""
        if not self.is_configured() or not self.is_connected():
            return {"success": False, "matches": None, "error": "Blockchain not configured or unreachable."}
        try:
            contract = self._contract()
            matches = contract.functions.verifyHash(assessment_id, report_hash).call()
            return {"success": True, "matches": matches, "error": None}
        except Exception as e:
            return {"success": False, "matches": None, "error": str(e)}


blockchain_client = BlockchainClient()
