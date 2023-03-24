pragma circom 2.0.0;

include "comparators.circom";

// signal `out` will be the average of input signals `in`. It uses integer division while diving the sum of input signals. Each input must be at most `maxBitsInput` bits
template Average(numInputs, maxBitsInput) {
    signal input in[numInputs];
    signal output out;

    // For intermediate sums
    signal intermediate[numInputs];
    signal remainder;

    // To check each input is of at most `maxBitsInput` bits
    component validations[numInputs];
    
    validations[0] = Num2Bits(maxBitsInput);
    validations[0].in <== in[0];
    intermediate[0] <== in[0];

    for (var i=1; i<numInputs; i++) {
        validations[i] = Num2Bits(maxBitsInput);
        validations[i].in <== in[i];
        intermediate[i] <== intermediate[i-1] + in[i]; 
    }

    out <-- intermediate[numInputs-1] \ numInputs;
    remainder <-- intermediate[numInputs-1] % numInputs;
    intermediate[numInputs-1] === (out * numInputs) + remainder;
}

/*
`out` is 1 if average of inputs signals `in` is less than signal `max`, 0 otherwise.
Each input must be at most `maxBitsInput` bits
*/
template AverageLessThan(numInputs, maxBitsInput) {
    signal input in[numInputs];
    signal input max;
    signal output out;

    signal average;
    
    component avg = Average(numInputs, maxBitsInput);
    for (var i=0; i<numInputs; i++) {
        avg.in[i] <== in[i];
    }
    average <== avg.out;

    component check = LessThan(maxBitsInput + numInputs - 1);
    
    check.a <== average;
    check.b <== max;
    out <== check.out;
}