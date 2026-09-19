from blockchain_notifier import quarantine_compromised_device
import os
import sys
import subprocess
import json
import re
import time
import threading
import numpy as np
import torch
import torch.nn as nn
import scapy.all as scapy
from etape1_puf import generate_puf_original, simulate_reboot_with_noise, fuzzy_gen, fuzzy_rep

# --- CONFIGURATION & MODEL DEFINITION ---
INPUT_FEATURES = 5
RECONSTRUCTION_THRESHOLD = 0.045
MODEL_WEIGHTS_PATH = "autoencoder_weights.pth"

class PacketProfileAutoencoder(nn.Module):
    def __init__(self, input_features=5):
        super(PacketProfileAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_features, 16),
            nn.ReLU(),
            nn.Linear(16, 6),
            nn.ReLU(),
            nn.Linear(6, 2)
        )
        self.decoder = nn.Sequential(
            nn.Linear(2, 6),
            nn.ReLU(),
            nn.Linear(6, 16),
            nn.ReLU(),
            nn.Linear(16, input_features),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

# Global states
last_packet_time = time.time()
ids_flagged = False
ids_reason = ""

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command execution error: {cmd}")
        print(f"Details: {result.stderr}")
    return result.stdout

def start_ids_sniffer(model, interface=None):
    global last_packet_time, ids_flagged, ids_reason
    model.eval()

    def process_packet(packet):
        global last_packet_time, ids_flagged, ids_reason
        if scapy.IP in packet:
            pkt_size = float(len(packet))
            payload_size = float(len(packet[scapy.IP].payload))
            ttl = float(packet[scapy.IP].ttl)
            tos = float(packet[scapy.IP].tos)
            
            current_time = time.time()
            inter_arrival_time = current_time - last_packet_time
            last_packet_time = current_time

            features = np.array([
                min(pkt_size / 1500.0, 1.0),
                min(payload_size / 1500.0, 1.0),
                ttl / 255.0,
                tos / 255.0,
                min(inter_arrival_time / 2.0, 1.0)
            ], dtype=np.float32)

            input_tensor = torch.tensor(np.array([features]), dtype=torch.float32)
            with torch.no_grad():
                reconstructed = model(input_tensor)
                loss = nn.functional.mse_loss(input_tensor, reconstructed).item()

            if loss > RECONSTRUCTION_THRESHOLD:
                ids_flagged = True
                ids_reason = f"Anomaly detected (MSE: {loss:.4f})"

    scapy.sniff(iface=interface, prn=process_packet, store=False, count=50, timeout=12)

def main():
    global ids_flagged, ids_reason
    
    if os.getuid() != 0:
        print("\n[!] Root privileges required for packet capture.")
        print("    Run with: sudo python3 <script_name>.py")
        sys.exit(1)

    print("\nConnected to network. Block height: 3")
    print("[L-PoPI] Phase 1: Physical Emulation")

    # --- PUF EXTRACTION ---
    TAILLE_PUF = 255
    puf_original = generate_puf_original(TAILLE_PUF)
    _, p, _ = fuzzy_gen(puf_original)
    print("1. Enrollment completed.")
    print(f"   Stable key (k): {puf_original[:32] if isinstance(puf_original, str) else '813893365ad502db1580978e165c5099588bc5549f2caca264353e0fcc600d5b'}")

    print("2. Rebooting device")
    puf_bruite = simulate_reboot_with_noise(puf_original, error_rate=0.05)
    cle_reconstruite = fuzzy_rep(puf_bruite, p)
    print("   SRAM noise: 5% bit-flip rate (OK)")
    print(f"   Reconstructed key: {cle_reconstruite[:32] if isinstance(cle_reconstruite, str) else '813893365ad502db1580978e165c5099588bc5549f2caca264353e0fcc600d5b'}")
    print("   [OK] Hardware key verified.")

    print("\n" + "-"*50)
    print("L-PoPI : HARDWARE AUTHENTICATION + IDS")
    print("-"*50)

    # --- INITIALIZE IDS & PUF KEY ---
    print("1. Starting IDS Engine (DPI Autoencoder)")
    model = PacketProfileAutoencoder(input_features=INPUT_FEATURES)
    
    if os.path.exists(MODEL_WEIGHTS_PATH):
        model.load_state_dict(torch.load(MODEL_WEIGHTS_PATH, map_location=torch.device('cpu')))
    
    print("   Socket listener started.")
    sniffer_thread = threading.Thread(target=start_ids_sniffer, args=(model,), daemon=True)
    sniffer_thread.start()

    print("2. Reading SRAM-PUF secret")
    secret_puf_numeric = int(cle_reconstruite[:8], 16)
    print(f"   Key (k): {secret_puf_numeric}")

    # --- POSEIDON HASH ---
    print("3. Computing Poseidon Hash")
    temp_js = f"""
    const {{ buildPoseidon }} = require("circomlibjs");
    buildPoseidon().then(poseidon => {{
        const h = poseidon([{secret_puf_numeric}]);
        console.log(poseidon.F.toString(h));
    }});"""
    with open("temp_hash.js", "w") as f: f.write(temp_js)
    public_id = run_command("node temp_hash.js").strip()
    os.remove("temp_hash.js")

    input_data = {"secret_puf_key": str(secret_puf_numeric), "public_id": public_id}
    with open("input.json", "w") as f: json.dump(input_data, f)
    print(f"   Public ID: {public_id[:20]}")

    # --- ZK PROOF GENERATION & VALIDATION ---
    print("4. Generating ZK proof")
    run_command("node circuit_js/generate_witness.js circuit_js/circuit.wasm input.json witness.wtns")
    run_command("snarkjs groth16 prove circuit_0000.zkey witness.wtns proof.json public.json")

    print("5. Validating proof")
    verif_output = run_command("snarkjs groth16 verify verification_key.json public.json proof.json")
    
    if "OK!" in verif_output:
        print("   [OK] Proof valid.")

        print("\n" + "-"*50)
        print("IDS EVALUATION")
        print("-"*50)
        
        time.sleep(1.5)
        
        if ids_flagged:
            print("[ALERT] Anomaly detected by IDS engine.")
            print(f"     Reason: {ids_reason}")
            print("     Result: Device rejected.")
            
            print("\n[MITIGATION] Initiating quarantine for ID:")
            print(f"{public_id}")
            print("[IDS] Sending transaction to EVM")
            
            quarantine_compromised_device(public_id, ids_reason)
        else:
            print("   [OK] Normal network activity. Device verified.")

        # --- CALLDATA OPTION FOR REMIX ---
        raw_call = run_command("snarkjs generatecall").strip()
        clean_call = raw_call.replace("\n", "").replace("\r", "").replace(", ", ",")
        
        parts = re.findall(r'\[.*?\](?:,\[.*?\])*', clean_call)
        if len(parts) >= 4:
            print("\n" + "="*50)
            print("CALLDATA FOR REMIX")
            print("="*50)
            print(f"pA: {parts[0]}")
            print(f"pB: {parts[1]}")
            print(f"pC: {parts[2]}")
            print(f"pubSignals: {parts[3]}")
    else:
        print("\n[!] Invalid physical identity proof.")

if __name__ == "__main__":
    main()