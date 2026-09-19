import os
import sys
import requests
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

# ==========================================
# CONFIGURATION & ENVIRONMENT SETUP
# ==========================================
ESP32_URL = os.getenv("ESP32_URL", "http://192.168.3.69/proof")

# Default Sepolia RPC (Override via environment variable if needed)
RPC_URL = os.getenv("RPC_URL", "https://rpc.sepolia.org")

# Fetch credentials and address from environment variables or set fallbacks
PRIVATE_KEY = os.getenv("RELAYER_PRIVATE_KEY", "0x0000000000000000000000000000000000000000000000000000000000000001")
CONTRACT_ADDRESS_RAW = os.getenv("CONTRACT_ADDRESS", "0x0000000000000000000000000000000000000000")

# ABI matching the Hardware Attestation Smart Contract
CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "int256", "name": "_tempScaled", "type": "int256"},
            {"internalType": "uint256", "name": "_humiScaled", "type": "uint256"},
            {"internalType": "uint256", "name": "_nonce", "type": "uint256"},
            {"internalType": "uint256", "name": "_execUs", "type": "uint256"},
            {"internalType": "bytes32", "name": "_commitment", "type": "bytes32"}
        ],
        "name": "verifyAttestation",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def fetch_proof_from_esp32(url: str) -> dict:
    """Fetches hardware proof payload from the ESP32 node."""
    print(f"[*] Fetching live proof from ESP32 at {url}...")
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"[+] Payload received successfully!")
        return data
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP Error fetching proof from ESP32: {e}")
        return None

# ==========================================
# MAIN RELAYER EXECUTION
# ==========================================
def relay_proof():
    # 1. Address Validation
    try:
        contract_address = Web3.to_checksum_address(CONTRACT_ADDRESS_RAW)
    except ValueError:
        print(f"[!] INVALID CONTRACT ADDRESS: '{CONTRACT_ADDRESS_RAW}' is not a valid 20-byte hex address.")
        print("    Set your contract address using: export CONTRACT_ADDRESS='0xYourContractAddress'")
        sys.exit(1)

    # 2. Connect to Ethereum Node
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    
    # Inject PoA middleware for testnets like Sepolia/Polygon/BSC
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    if not w3.is_connected():
        print(f"[!] Failed to connect to Web3 RPC node at {RPC_URL}")
        sys.exit(1)

    # Load account
    try:
        account = w3.eth.account.from_key(PRIVATE_KEY)
    except Exception as e:
        print(f"[!] INVALID PRIVATE KEY: {e}")
        print("    Set your key using: export RELAYER_PRIVATE_KEY='0xYourPrivateKey'")
        sys.exit(1)

    relayer_address = account.address
    balance = w3.from_wei(w3.eth.get_balance(relayer_address), 'ether')
    print(f"[*] Connected to Web3 RPC: {RPC_URL}")
    print(f"[*] Relayer Address: {relayer_address}")
    print(f"[*] Relayer Balance: {balance:.4f} ETH")

    if balance == 0:
        print("[!] WARNING: Relayer balance is 0 ETH. Transaction will fail without gas funds.")

    # 3. Fetch Proof from ESP32
    proof_data = fetch_proof_from_esp32(ESP32_URL)
    if not proof_data:
        sys.exit(1)

    # 4. Format/Scale Variables for Solidity Types
    temp_scaled = int(round(proof_data["temp"] * 100))
    humi_scaled = int(round(proof_data["humi"] * 100))
    nonce = int(proof_data["nonce"])
    exec_us = int(proof_data["exec_us"])
    
    # Format hex string commitment to 32-byte array
    commit_hex = proof_data["commitment"]
    if not commit_hex.startswith("0x"):
        commit_hex = "0x" + commit_hex
    commitment_bytes32 = bytes.fromhex(commit_hex[2:])

    print(f"\n[*] Transformed Attestation Payload:")
    print(f"    ├─ Temp (100x fixed-point): {temp_scaled} (Raw: {proof_data['temp']}°C)")
    print(f"    ├─ Humi (100x fixed-point): {humi_scaled} (Raw: {proof_data['humi']}%)")
    print(f"    ├─ Session Nonce          : {nonce}")
    print(f"    ├─ Execution Overhead     : {exec_us} µs")
    print(f"    └─ Poseidon Commitment    : {commit_hex}")

    # 5. Build Transaction
    contract = w3.eth.contract(address=contract_address, abi=CONTRACT_ABI)
    nonce_tx = w3.eth.get_transaction_count(relayer_address)

    tx_params = {
        "from": relayer_address,
        "nonce": nonce_tx,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id
    }

    tx_builder = contract.functions.verifyAttestation(
        temp_scaled,
        humi_scaled,
        nonce,
        exec_us,
        commitment_bytes32
    )

    # Estimate Gas Limit dynamically
    try:
        estimated_gas = tx_builder.estimate_gas({"from": relayer_address})
        tx_params["gas"] = int(estimated_gas * 1.2)  # 20% safety margin
        print(f"[*] Estimated Gas: {estimated_gas} units (Gas limit set to {tx_params['gas']})")
    except Exception as e:
        print(f"[!] Gas estimation warning: {e}. Defaulting gas limit to 200,000.")
        tx_params["gas"] = 200000

    built_tx = tx_builder.build_transaction(tx_params)

    # 6. Sign and Broadcast
    print("\n[*] Signing and broadcasting Web3 transaction...")
    signed_tx = w3.eth.account.sign_transaction(built_tx, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    print(f"[+] Transaction Broadcasted!")
    print(f"    └─ Transaction Hash: {w3.to_hex(tx_hash)}")
    print("[*] Awaiting on-chain execution confirmation...")

    # 7. Confirm Receipt
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    
    if tx_receipt["status"] == 1:
        print(f"\n[SUCCESS] Hardware Proof Verified On-Chain!")
        print(f"    ├─ Block Number: #{tx_receipt['blockNumber']}")
        print(f"    ├─ Gas Used    : {tx_receipt['gasUsed']}")
        print(f"    └─ Block Explorer: https://sepolia.etherscan.io/tx/{w3.to_hex(tx_hash)}")
    else:
        print(f"\n[!] TRANSACTION REVERTED: Execution failed on-chain.")

if __name__ == "__main__":
    relay_proof()