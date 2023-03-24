pragma circom 2.0.0;

// Does integer divsion `a / b`. Signal `q` is set to the quotient and `r` to remainder.
template IntegerDivision() {
    signal input a;
    signal input b;
    signal output q;
    signal output r;

    q <-- a \ b;
    r <-- a % b;

    a === q * b + r; 
}

template Division(divisor) {
    signal input in1;
    signal input in2;
    signal output q;
    signal output r;
    signal c;

    c <== (in1 * in2);

    component div = IntegerDivision();
    
    div.a <== c;
    div.b <== divisor;

    q <== div.q;
    r <== div.r;

}

component main = Division(24);
