import sys
from web3 import Web3
from eth_account import Account

# ==========================================
# CONFIGURATION SETTINGS
# ==========================================
RPC_ENDPOINT = "http://127.0.0.1:8545" 
CONTRACT_ADDRESS = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
IDS_OPERATOR_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# ==========================================
# WEB3 INITIALIZATION
# ==========================================
web3 = Web3(Web3.HTTPProvider(RPC_ENDPOINT))

if not web3.is_connected():
    print("[-] Blockchain Error: Cannot connect to RPC node.")
    # Don't kill the whole app if local blockchain is down, just skip fallback
else:
    print(f"[+] Connected to network. Block height: {web3.eth.block_number}")

try:
    operator_account = Account.from_key(IDS_OPERATOR_PRIVATE_KEY)
except Exception:
    pass

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

# Initialize contract pointer
if web3.is_connected():
    checksum_address = web3.to_checksum_address(CONTRACT_ADDRESS)
    contract = web3.eth.contract(address=checksum_address, abi=MINIMAL_IDS_ABI)

# ==========================================
# CORE AUTOMATED QUARANTINE FUNCTION
# ==========================================
def quarantine_compromised_device(hardware_id_str: str, logs_payload: str):
    """
    Submits an on-chain transaction automatically flagging a hardware node's status 
    as malicious, barring it from future validations.
    """
    if not web3.is_connected():
        print("[-] Aborting quarantine tx: No active blockchain network connection.")
        return False

    # Convert the public_id string from snarkjs/circom into a uint256 integer
    try:
        if hardware_id_str.startswith("0x"):
            hardware_id = int(hardware_id_str, 16)
        else:
            hardware_id = int(hardware_id_str)
    except ValueError:
        print(f"[-] Data conversion error: Cannot cast {hardware_id_str} to uint256 integer.")
        return False

    print(f"\n[!] AUTOMATED QUARANTINE TRIGGERED FOR PUBLIC IDENTITY:\n    -> {hardware_id}")
    
    try:
        nonce = web3.eth.get_transaction_count(operator_account.address)
        
        built_tx = contract.functions.reportIntrusion(
            hardware_id,
            logs_payload
        ).build_transaction({
            'from': operator_account.address,
            'nonce': nonce,
            'gas': 120000,
            'gasPrice': web3.eth.gas_price
        })
        
        signed_tx = web3.eth.account.sign_transaction(built_tx, private_key=IDS_OPERATOR_PRIVATE_KEY)
        print("[*] Broadcasting intrusion report payload packet to EVM ledger...")
        
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"[+] Intrusion Tx Hash broadcasted: {tx_hash.hex()}")
        
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        if receipt['status'] == 1:
            print(f"[SUCCESS] On-chain state updated. Device quarantined. Gas used: {receipt['gasUsed']}")
            return True
        else:
            print("[-] On-chain reversion: Transaction execution failed on EVM contract.")
            return False
            
    except Exception as error:
        print(f"[-] Execution error during automated quarantine pipeline: {error}")
        return False