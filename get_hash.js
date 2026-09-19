const { buildPoseidon } = require("circomlibjs");

async function run() {
    // On attend que le constructeur Poseidon soit prêt
    const poseidon = await buildPoseidon();
    
    const secret = "12345";
    
    // Calcul du hash
    const hash = poseidon([secret]);
    
    // On convertit le résultat en un format lisible (nombre décimal)
    console.log("Votre public_id pour input.json est :");
    console.log(poseidon.F.toString(hash));
}

run();
