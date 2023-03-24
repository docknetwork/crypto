pragma circom 2.0.0;

include "comparators.circom";

template OR() {
    signal input a;
    signal input b;
    signal output out;

    out <== a + b - a*b;
}

// `out` is set to 1 if in1 > in3 or in2 > in4, else 0
template GreaterThanOr(maxBitsInput) {
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal output out;

    component check1 = GreaterThan(maxBitsInput);
    check1.a <== in1;
    check1.b <== in3;

    component check2 = GreaterThan(maxBitsInput);
    check2.a <== in2;
    check2.b <== in4;

    component check3 = OR();
    check3.a <== check1.out;
    check3.b <== check2.out;

    out <== check3.out;
}