import numpy as np
import matplotlib.pyplot as plt
from etape1_puf import generate_puf_original, simulate_reboot_with_noise, fuzzy_gen, fuzzy_rep

def evaluate_robustness():
    # Paramètres de la simulation
    TAILLE_PUF = 255
    NB_TESTS_PER_POINT = 100  # Nombre de tentatives par niveau de bruit
    noise_levels = np.linspace(0, 0.25, 20)  # Taux de bruit de 0% à 25%
    success_rates = []

    print("Démarrage de la simulation de robustesse...")

    # 1. Génération du secret original (Enrollment)
    puf_original = generate_puf_original(TAILLE_PUF)
    _, p, _ = fuzzy_gen(puf_original)

    for noise in noise_levels:
        success_count = 0
        for _ in range(NB_TESTS_PER_POINT):
            # 2. Simulation du bruit (Reconstruction attempt)
            puf_bruite = simulate_reboot_with_noise(puf_original, error_rate=noise)
            
            try:
                # 3. Tentative de reconstruction de la clé stable k
                cle_reconstruite = fuzzy_rep(puf_bruite, p)
                success_count += 1
            except:
                # Si la distance de Hamming est trop élevée, l'extraction échoue
                pass
        
        rate = (success_count / NB_TESTS_PER_POINT) * 100
        success_rates.append(rate)
        print(f"Bruit: {noise:.2%} | Taux de réussite: {rate}%")

    # --- Tracé du graphique ---
    plt.figure(figsize=(10, 6))
    plt.plot(noise_levels * 100, success_rates, marker='o', linestyle='-', color='#2c3e50', linewidth=2)
    
    # Mise en forme académique
    plt.title('Robustness of L-PoPI Authentication against PUF Noise', fontsize=14)
    plt.xlabel('Environmental Noise Level / Bit Error Rate (BER) %', fontsize=12)
    plt.ylabel('Authentication Success Rate (%)', fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.axvline(x=15, color='r', linestyle='--', label='Theoretical Correction Limit (15%)')
    plt.legend()
    
    # Sauvegarde pour le papier LaTeX
    plt.savefig('robustness_curve.png', dpi=300)
    plt.show()

if __name__ == "__main__":
    evaluate_robustness()