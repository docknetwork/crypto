pragma circom 2.0.0;

/*This circuit template checks that y = (x + z)^2 + z + 1 */

template Test2 () {  
    // Declaration of signals.  
    signal input x;  
    signal input z;  
    signal output y;  

    // Constraints.  
    
    // This creates less constraints 
    // signal t1 <== (x + z) * (x + z);
    // y <== t1 + z + 1; 

    // This creates more constraints 
    signal t1 <== x * x;
    signal t2 <== z * z;
    signal t3 <== 2 * x * z;
    y <== t1 + t2 + t3 + z + 1;

}

component main = Test2();