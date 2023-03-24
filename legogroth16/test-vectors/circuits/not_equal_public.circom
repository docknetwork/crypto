pragma circom 2.0.0;

include "comparators.circom";

template NotEqualPublic () {
    signal input in;
    signal input pub;
    signal output out;

    component isz = IsZero();
    isz.in <== in - pub;
    out <== 1 - isz.out;
}

component main {public [pub]} = NotEqualPublic();