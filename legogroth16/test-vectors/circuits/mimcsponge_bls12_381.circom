pragma circom 2.0.0;

include "./mimc_constants.circom";
include "./mimcsponge.circom";

template MimcSponge(nInputs, nOutputs) {
    signal input in[nInputs];
    signal input k;
    signal output out[nOutputs];

    component mimc = MiMCSponge(nInputs, nOutputs, 220, MIMC_SPONGE_BLS12_381());
    for (var i=0; i<nInputs; i++) {
        mimc.ins[i] <== in[i];
    }
    mimc.k <== k;

    for (var i=0; i<nOutputs; i++) {
        out[i] <== mimc.outs[i];
    }
}

component main = MimcSponge(2, 3);