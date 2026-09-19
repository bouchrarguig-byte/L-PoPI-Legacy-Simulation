pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

template L_PoPI() {
    signal input secret_puf_key;
    signal input public_id;

    component hasher = Poseidon(1);
    hasher.inputs[0] <== secret_puf_key;

    hasher.out === public_id;
}

component main {public [public_id]} = L_PoPI();
