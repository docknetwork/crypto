pragma circom 2.0.0;

include "./poseidon.circom";

template PoseidonHash(nInputs) {
    signal input in[nInputs];
    signal output out;

    component poseidon = Poseidon(nInputs, 1);
    for (var i=0; i<nInputs; i++) {
        poseidon.inputs[i] <== in[i];
    }

    out <== poseidon.out;
}

component main = PoseidonHash(5);