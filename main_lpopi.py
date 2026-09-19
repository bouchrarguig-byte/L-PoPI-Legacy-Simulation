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
RECONSTRUCTION_THRESHOLD = 0.045  # Tuned metric for physical vs virtual signatures
MODEL_WEIGHTS_PATH = "autoencoder_weights.pth"

class PacketProfileAutoencoder(nn.Module):
    def __init__(self, input_features=5):
        super(PacketProfileAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_features, 16),
            nn.ReLU(),
            nn.Linear(16, 6),
            nn.ReLU(),
            nn.Linear(6, 2)  # Latent space bottleneck representing clean hardware traffic profile
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

# Global states for parallel execution coordination
last_packet_time = time.time()
ids_flagged = False
ids_reason = ""

def run_command(cmd):
    """Exécute une commande système et capture la sortie proprement."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Erreur lors de l'exécution de : {cmd}")
        print(f"Détail : {result.stderr}")
    return result.stdout

# --- COGNITIVE ADAPTIVE LAYER: DEEP PACKET INSPECTION & AUTOMATED ANOMALY MAPPING ---
def start_ids_sniffer(model, interface=None):
    """Captures live framework interaction packets to evaluate network behaviors."""
    global last_packet_time, ids_flagged, ids_reason
    model.eval()

    def process_packet(packet):
        global last_packet_time, ids_flagged, ids_reason
        if scapy.IP in packet:
            # Deep Packet Inspection (DPI) extraction metrics
            pkt_size = float(len(packet))
            payload_size = float(len(packet[scapy.IP].payload))
            ttl = float(packet[scapy.IP].ttl)
            tos = float(packet[scapy.IP].tos)
            
            current_time = time.time()
            inter_arrival_time = current_time - last_packet_time
            last_packet_time = current_time

            # Structuring normalized inputs bounded safely between [0, 1]
            features = np.array([
                min(pkt_size / 1500.0, 1.0),
                min(payload_size / 1500.0, 1.0),
                ttl / 255.0,
                tos / 255.0,
                min(inter_arrival_time / 2.0, 1.0)
            ], dtype=np.float32)

            # OPTIMIZED: Converted to native numpy array container before tensor creation to remove warning overhead
            input_tensor = torch.tensor(np.array([features]), dtype=torch.float32)
            with torch.no_grad():
                reconstructed = model(input_tensor)
                loss = nn.functional.mse_loss(input_tensor, reconstructed).item()

            if loss > RECONSTRUCTION_THRESHOLD:
                ids_flagged = True
                ids_reason = f"DPI Anomaly Verified! MSE: {loss:.4f} (Virtualized stack footprint mismatch)"

    # Listens continuously for up to 50 packets or until the verification stage completes
    scapy.sniff(iface=interface, prn=process_packet, store=False, count=50, timeout=12)

# --- MAIN UNIFIED INTEGRATION PIPELINE ---
def main():
    global ids_flagged, ids_reason
    
    # Enforce administrative privileges required for Scapy live sniffing
    if os.getuid() != 0:
        print("\n[!] CRITICAL ERROR: Administrative root privileges required for network DPI capturing.")
        print("    Please run this script using: sudo python3 <script_name>.py")
        sys.exit(1)

    print("\n" + "="*50)
    print("      L-PoPI v2 : AUTHENTIFICATION MATÉRIELLE + IDS")
    print("="*50)

    # --- INITIALIZE COGNITIVE LOGICAL LAYER ---
    print("\n[0] Initialisation du moteur IDS (DPI Autoencoder)...")
    model = PacketProfileAutoencoder(input_features=INPUT_FEATURES)
    
    # Load trained weights matching your paper's 95-96% accuracy parameter assertions
    if os.path.exists(MODEL_WEIGHTS_PATH):
        print(f"    -> Chargement des poids du modèle validé: {MODEL_WEIGHTS_PATH}")
        model.load_state_dict(torch.load(MODEL_WEIGHTS_PATH, map_location=torch.device('cpu')))
    else:
        print(f"    [!] WARNING: {MODEL_WEIGHTS_PATH} introuvable. Utilisation de poids non-entraînés.")
    
    print("    -> Démarrage de l'écoute réseau asynchrone (Scapy Thread)...")
    sniffer_thread = threading.Thread(target=start_ids_sniffer, args=(model,), daemon=True)
    sniffer_thread.start()

    # --- ÉTAPE 1 : EXTRACTION DU SECRET PUF (PHYSIQUE) ---
    print("\n[1] Extraction du secret physique (SRAM-PUF)...")
    TAILLE_PUF = 255
    puf_original = generate_puf_original(TAILLE_PUF)
    _, p, _ = fuzzy_gen(puf_original)
    
    puf_bruite = simulate_reboot_with_noise(puf_original, error_rate=0.05)
    cle_reconstruite = fuzzy_rep(puf_bruite, p)
    
    secret_puf_numeric = int(cle_reconstruite[:8], 16)
    print(f"    -> Secret stabilisé (k) : {secret_puf_numeric}")

    # --- ÉTAPE 2 : CALCUL DE L'ID PUBLIC (POSEIDON) ---
    print("\n[2] Calcul de l'identité publique (Poseidon Hash)...")
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
    print(f"    -> Identity Public ID : {public_id[:20]}...")

    # --- ÉTAPE 3 : GÉNÉRATION DE LA PREUVE ---
    print("\n[3] Génération de la preuve Zero-Knowledge...")
    run_command("node circuit_js/generate_witness.js circuit_js/circuit.wasm input.json witness.wtns")
    run_command("snarkjs groth16 prove circuit_0000.zkey witness.wtns proof.json public.json")

    # --- ÉTAPE 4 : VÉRIFICATION LOCALE & RÉSULTATS LOGIQUES ---
    print("\n[4] Vérification de la preuve...")
    verif_output = run_command("snarkjs groth16 verify verification_key.json public.json proof.json")
    
    if "OK!" in verif_output:
        print("    -> [STATUS] OK : Preuve cryptographique matérielle valide.")
        
        print("\n" + "-"*50)
        print(" [IDS EVALUATION] CORRÉLATION DU COMPORTEMENT LOGIQUE NETWORK")
        print("-"*50)
        
        time.sleep(1.5) # Dynamic delay to gather localized network flows
        
        if ids_flagged:
            print(f" [!] EMULATION DETECTED : Alerte de la couche IDS.")
            print(f"     Raison : {ids_reason}")
            print(" [STATUS] REJECTED / QUARANTINE : Identité matérielle valide, mais signature réseau non-conforme.")
            
            # --- AUTOMATED ON-CHAIN QUARANTINE TRIGGER ---
            print("\n[-->] INITIALIZING CLOSED-LOOP CROSS-LAYER MITIGATION...")
            print("      Submitting malicious hardware identity directly to the settlement engine...")
            quarantine_compromised_device(public_id, ids_reason)
        else:
            print("    -> [STATUS] OK : Comportement réseau sain. Aucun clone logiciel détecté.")
            print("    -> TRUST ANCHOR COMPLETE : Validation matérielle + Comportementale vérifiée.")

        # --- ÉTAPE 5 : FORMATAGE DU CALLDATA STABLE POUR REMIX ---
        print("\n" + "="*60)
        print(" [5] CALLDATA POUR LE SMART CONTRACT SOLIDIY (REMIX)")
        print("="*60)
        
        raw_call = run_command("snarkjs generatecall").strip()
        clean_call = raw_call.replace("\n", "").replace("\r", "").replace(", ", ",")
        
        print("\n--- OPTION A : ARGUMENT UNIQUE COMPACT ---")
        print(clean_call)

        parts = re.findall(r'\[.*?\](?:,\[.*?\])*', clean_call)
        if len(parts) >= 4:
            print("\n--- OPTION B : ARGUMENTS SÉPARÉS (REMIX PARAMS) ---")
            print(f"Arg [_pA] (uint256[2])      : {parts[0]}")
            print(f"Arg [_pB] (uint256[2][2])   : {parts[1]}")
            print(f"Arg [_pC] (uint256[2])      : {parts[2]}")
            print(f"Arg [_pubSignals] (uint256[1]) : {parts[3]}")
        print("\n" + "="*60)
    else:
        print("\n [!] ERREUR : La preuve de l'identité physique est invalide.")

if __name__ == "__main__":
    main()