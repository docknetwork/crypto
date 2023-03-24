pragma circom 2.0.0;

include "comparators.circom";

// `out` is set to sum of given inputs `in`. Each input must be at most `maxBitsInput` bits
template SumOfInputs(numInputs, maxBitsInput) {
    signal input in[numInputs];
    signal output out;

    // To check each input is of at most `maxBitsInput` bits
    component validations[numInputs];
    // For intermediate sums
    signal intermediate[numInputs];

    validations[0] = Num2Bits(maxBitsInput);
    validations[0].in <== in[0];
    intermediate[0] <== in[0];

    for (var i=1; i<numInputs; i++) {
        validations[i] = Num2Bits(maxBitsInput);
        validations[i].in <== in[i];
        intermediate[i] <== intermediate[i-1] + in[i]; 
    }

    out <== intermediate[numInputs-1];
}

/*
`out` is 1 if difference of sum of inputs signals `inA` and sum of inputs signals `inB` is more than signal `min`, 0 otherwise.
Each input must be at most `maxBitsInput` bits
*/
template DifferenceOfArraySum(numInputsA, numInputsB, maxBitsInput) {
    signal input inA[numInputsA];
    signal input inB[numInputsB];
    signal input min;
    signal output out;

    component sumA = SumOfInputs(numInputsA, maxBitsInput);
    for (var i=0; i<numInputsA; i++) {
        sumA.in[i] <== inA[i];
    }

    component sumB = SumOfInputs(numInputsB, maxBitsInput);
    for (var i=0; i<numInputsB; i++) {
        sumB.in[i] <== inB[i];
    }

    component check = GreaterThan(maxBitsInput + numInputsA - 1);
    
    check.a <== sumA.out - sumB.out;
    check.b <== min;
    out <== check.out;
}