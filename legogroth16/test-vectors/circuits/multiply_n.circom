pragma circom 2.0.0;

template MultiplierN (n) {  

    // Declaration of signals.  
    signal input in[n];  
    signal output out;  

    signal intermediate[n];
    
    // Constraints.  
    intermediate[0] <== in[0];
    for (var i=1; i<n; i++) {
      intermediate[i] <== in[i] * intermediate[i-1];
    }
    out <== intermediate[n-1];
}

component main = MultiplierN(300);