import os
import sys
from web3 import Web3
from eth_account import Account

# ==========================================
# CONFIGURATION SETTINGS
# ==========================================
RPC_ENDPOINT = "http://127.0.0.1:8545" 

# FIXED: Set to your actual deployed contract address from Block 5
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

# This private key corresponds perfectly to the authorized operator (0x7099...)
IDS_OPERATOR_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# ==========================================
# WEB3 PIPELINE INITIALIZATION
# ==========================================
web3 = Web3(Web3.HTTPProvider(RPC_ENDPOINT))

if not web3.is_connected():
    print("[-] Critical Error: Cannot connect to the blockchain RPC node.")
    sys.exit(1)

print(f"[+] Connected to network. Block height: {web3.eth.block_number}")

# Derive the public address from the private key
try:
    operator_account = Account.from_key(IDS_OPERATOR_PRIVATE_KEY)
    print(f"[+] Operator Wallet Authenticated: {operator_account.address}")
except ValueError as e:
    print(f"[-] Private Key Error: {e}")
    sys.exit(1)

# Minimal Application Binary Interface (ABI) required to call reportIntrusion
MINIMAL_IDS_ABI = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "hardwareId", "type": "uint256"},
            {"internalType": "string", "name": "telemetryAlert", "type": "string"}
        ],
        "name": "reportIntrusion",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

# Instantiate the contract instance object
checksum_address = web3.to_checksum_address(CONTRACT_ADDRESS)
contract = web3.eth.contract(address=checksum_address, abi=MINIMAL_IDS_ABI)

# ==========================================
# CORE QUARANTINE FUNCTION
# ==========================================
def quarantine_compromised_device(hardware_id: int, logs_payload: str):
    """
    Submits an on-chain transaction flagging a hardware node's status 
    as malicious, barring it from future validations.
    """
    print(f"\n[*] Initializing quarantine sequence for hardware ID:\n    -> {hardware_id}")
    
    try:
        # Fetch current transaction count (nonce) for the operator address
        nonce = web3.eth.get_transaction_count(operator_account.address)
        
        # Build the contract transaction transaction
        built_tx = contract.functions.reportIntrusion(
            hardware_id,
            logs_payload
        ).build_transaction({
            'from': operator_account.address,
            'nonce': nonce,
            'gas': 120000,                      # Safe buffer ceiling for execution gas units
            'gasPrice': web3.eth.gas_price     # Dynamically fetch current network market gas pricing
        })
        
        # Sign the transaction locally using the operator's private key
        signed_tx = web3.eth.account.sign_transaction(built_tx, private_key=IDS_OPERATOR_PRIVATE_KEY)
        
        # Broadcast the signed raw transaction data stream to the network nodes
        print("[*] Broadcasting cryptographic payload transaction packet...")
        
        # UPDATED: Changed from deprecated .rawTransaction to snake_case .raw_transaction
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        print(f"[+] Transaction broadcasted successfully. Hash: {tx_hash.hex()}")
        
        # Await network receipt mining status confirmation loop
        print("[*] Awaiting on-chain validation confirmation receipt...")
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        if receipt['status'] == 1:
            print(f"[SUCCESS] Node {hardware_id} marked as malicious. Gas used: {receipt['gasUsed']}")
        else:
            print("[-] Execution reverted: Transaction failed on-chain. Is the sender an authorized operator?")
            
    except Exception as error:
        print(f"[-] Execution error during runtime configuration pipeline: {error}")

# ==========================================
# EXECUTION ENTRYPOINT
# ==========================================
if __name__ == "__main__":
    # Test values derived from your successful transaction payload parameters
    TARGET_HARDWARE_ID = 14823674279905297681916571274289529554497664523066155880065578766158990092458
    ALERT_REASON = "DPI Autoencoder script triggered anomaly threshold violation matching spoof signature profiles."
    
    # Execute the quarantine command line action
    quarantine_compromised_device(TARGET_HARDWARE_ID, ALERT_REASON)
