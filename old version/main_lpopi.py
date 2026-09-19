import os
import subprocess
import json
import re
from etape1_puf import generate_puf_original, simulate_reboot_with_noise, fuzzy_gen, fuzzy_rep

def run_command(cmd):
    """Exécute une commande système et capture la sortie proprement."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Erreur lors de l'exécution de : {cmd}")
        print(f"Détail : {result.stderr}")
    return result.stdout

def main():
    print("\n" + "="*50)
    print("      L-PoPI : SYSTÈME D'AUTHENTIFICATION IOT")
    print("="*50)

    # --- ÉTAPE 1 : EXTRACTION DU SECRET PUF (PHYSIQUE) ---
    print("\n[1] Extraction du secret physique (SRAM-PUF)...")
    TAILLE_PUF = 255
    puf_original = generate_puf_original(TAILLE_PUF)
    _, p, _ = fuzzy_gen(puf_original)
    
    # Simulation du bruit (5%) et reconstruction de la clé stable
    puf_bruite = simulate_reboot_with_noise(puf_original, error_rate=0.05)
    cle_reconstruite = fuzzy_rep(puf_bruite, p)
    
    # Conversion du secret pour le circuit ZK (8 premiers caractères hex)
    secret_puf_numeric = int(cle_reconstruite[:8], 16)
    print(f"    -> Secret stabilisé (k) : {secret_puf_numeric}")

    # --- ÉTAPE 2 : CALCUL DE L'ID PUBLIC (POSEIDON) ---
    print("[2] Calcul de l'identité publique (Poseidon Hash)...")
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
    print("[3] Génération de la preuve Zero-Knowledge...")
    run_command("node circuit_js/generate_witness.js circuit_js/circuit.wasm input.json witness.wtns")
    run_command("snarkjs groth16 prove circuit_0000.zkey witness.wtns proof.json public.json")

    # --- ÉTAPE 4 : VÉRIFICATION LOCALE ---
    verif_output = run_command("snarkjs groth16 verify verification_key.json public.json proof.json")
    if "OK!" in verif_output:
        print("    -> [STATUS] OK : Preuve valide.")

        # --- ÉTAPE 5 : FORMATAGE POUR REMIX (STRICT) ---
        print("\n" + "="*60)
        print(" [5] CALLDATA POUR LE SMART CONTRACT (REMIX)")
        print("="*60)
        
        # On récupère le calldata formaté par snarkjs
        raw_call = run_command("snarkjs generatecall").strip()
        
        # Nettoyage pour le mode "Champ Unique"
        clean_call = raw_call.replace("\n", "").replace("\r", "").replace(", ", ",")
        
        print("\n--- OPTION A : COPIER LE BLOC COMPLET ---")
        print("(À coller directement dans le champ 'verifyProof')")
        print(clean_call)

        # Extraction des parties individuelles pour le mode "Champs Séparés"
        # Utilisation de regex pour isoler les 4 arguments [a, b, c, input]
        parts = re.findall(r'\[.*?\](?:,\[.*?\])*', clean_call)
        
        if len(parts) >= 4:
            print("\n--- OPTION B : COPIER CHAMP PAR CHAMP ---")
            print("(Cliquez sur la flèche de 'verifyProof' dans Remix)")
            print(f"Arg [a] (uint256[2])      : {parts[0]}")
            print(f"Arg [b] (uint256[2][2])   : {parts[1]}")
            print(f"Arg [c] (uint256[2])      : {parts[2]}")
            print(f"Arg [input] (uint256[1])  : {parts[3]}")
        
        print("\n" + "="*60)
    else:
        print("\n [!] ÉCHEC : La preuve est invalide.")

if __name__ == "__main__":
    main()