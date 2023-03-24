pragma circom 2.0.0;

include "comparators.circom";

/* 
This circuit checks that all inputs are different. Compares each pair of inputs and for each comparison, it adds 1 or 0 depending 
on whether they are equal or not. If all are the different then the signal should be 0 at the end.
*/

template AllDifferent(n) {
    signal input in[n];
    signal output out;

    var numEqualityChecks = (n*(n-1)) / 2;  // n-1 + n-2 + ... 1
    // Each signal will have value equal to the number of equalities it has seen
    signal intermediate[numEqualityChecks + 1];
    intermediate[0] <== 0;

    var offset = 1;

    component checks[numEqualityChecks];
    
    // For each pair of elements, check that they are not equal.
    for (var i=0; i<n-1; i++) {
        for (var j=i+1; j<n; j++) {
            // checks[offset - 1].out must be 0 if its inputs are not eual
            checks[offset - 1] = IsEqual();
            checks[offset - 1].a <== in[i];
            checks[offset - 1].b <== in[j];
            // intermediate[offset] would be the sum of `offset` pairs
            intermediate[offset] <== intermediate[offset-1] + checks[offset - 1].out;

            offset = offset + 1;
        }
    }

    component isz = IsZero();
    isz.in <== intermediate[numEqualityChecks];

    isz.out ==> out;
}