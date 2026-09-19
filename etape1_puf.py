import numpy as np
import hashlib

def generate_puf_original(size=255):
    """Simule l'empreinte unique du silicium au premier démarrage (Enrôlement)"""
    return np.random.randint(0, 2, size)

def simulate_reboot_with_noise(original_puf, error_rate=0.05):
    """Simule un redémarrage avec 5% d'erreurs (bruit thermique/électrique)"""
    noisy_puf = original_puf.copy()
    num_errors = int(len(original_puf) * error_rate)
    indices_erreurs = np.random.choice(len(original_puf), num_errors, replace=False)
    for idx in indices_erreurs:
        noisy_puf[idx] = 1 - noisy_puf[idx]
    return noisy_puf

def fuzzy_gen(puf_bits, repetition=5):
    """PHASE GEN : Crée la clé stable et les données d'aide (Helper Data)"""
    # On définit la taille de la clé stable
    longueur_cle = len(puf_bits) // repetition
    stable_key_bits = np.random.randint(0, 2, longueur_cle)
    
    # Répétition pour la correction d'erreur (Code de répétition)
    repeated_key = np.repeat(stable_key_bits, repetition)
    
    # Helper Data (p) = PUF XOR Clé Répétée
    helper_data = puf_bits ^ repeated_key
    
    # Hash final pour obtenir la clé cryptographique k
    k = hashlib.sha256(stable_key_bits.tobytes()).hexdigest()
    return k, helper_data, stable_key_bits

def fuzzy_rep(noisy_puf, helper_data, repetition=5):
    """PHASE REP : Retrouve la clé exacte malgré le bruit"""
    # On annule le masque avec le Helper Data
    recovered_repeated_key = noisy_puf ^ helper_data
    
    # Vote majoritaire : si sur 5 bits, on a trois '1', on déduit que le bit original était '1'
    reconstructed_bits = []
    for i in range(0, len(recovered_repeated_key), repetition):
        chunk = recovered_repeated_key[i:i+repetition]
        reconstructed_bits.append(1 if np.sum(chunk) > (repetition / 2) else 0)
    
    k = hashlib.sha256(np.array(reconstructed_bits).tobytes()).hexdigest()
    return k

# --- EXECUTION DE LA SIMULATION ---
print("--- [L-PoPI] Etape 1 : Simulation Physique ---")

# 1. Enrôlement (Fabrication de l'objet)
puf_original = generate_puf_original()
cle_initiale, p, bits_secrets = fuzzy_gen(puf_original)

print(f"\n1. Enrôlement terminé.")
print(f"   Clé stable (k) générée : {cle_initiale}")
print(f"   Données d'aide (p) stockées : {p[:10]}... (Total {len(p)} bits)")

# 2. Redémarrage (Usage quotidien dans le réseau DePIN)
puf_bruite = simulate_reboot_with_noise(puf_original, error_rate=0.05)
cle_reconstruite = fuzzy_rep(puf_bruite, p)

print(f"\n2. Redémarrage de l'appareil...")
print(f"   Bruit détecté : 5% des bits ont changé.")
print(f"   Clé reconstruite : {cle_reconstruite}")

# 3. Vérification de l'intégrité
if cle_initiale == cle_reconstruite:
    print("\n[SUCCESS] L'intégrité physique est prouvée. La clé est identique !")
else:
    print("\n[FAILURE] Trop de bruit, l'identité a été perdue.")