pragma circom 2.0.0;

/*This circuit template checks that y = x^3 + x + 5.*/

template Test1 () {  
    // Declaration of signals.  
    signal input x;  
    signal output y;  

    // Constraints.  
    signal t1 <== x * x;
    signal t2 <== t1 * x;
    y <== t2 + x + 5; 
}

component main = Test1();