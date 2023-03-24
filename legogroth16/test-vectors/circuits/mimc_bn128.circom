pragma circom 2.0.0;

include "./mimc_constants.circom";
include "./mimc.circom";

template MultiMimcHash(nInputs) {
    signal input in[nInputs];
    signal input k;
    signal output out;

    component mimc = MultiMiMC7(nInputs, 220, MIMC7_BN128());
    for (var i=0; i<nInputs; i++) {
        mimc.in[i] <== in[i];
    }
    mimc.k <== k;

    out <== mimc.out;
}

component main = MultiMimcHash(8);