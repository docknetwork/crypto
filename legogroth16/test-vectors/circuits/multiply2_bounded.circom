pragma circom 2.0.0;

/*This circuit template checks that c is the multiplication of a and b and both a and b are 64-bit non-zero numbers*/

template CheckBits(n) {
    signal input in;
    signal bits[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] -1 ) === 0;
        lc1 += bits[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

template Multiplier(n) {
    signal input a;
    signal input b;
    signal output c;
    signal inva;
    signal invb;

    component checkA = CheckBits(n);
    component checkB = CheckBits(n);

    checkA.in <== a;
    checkB.in <== b;

    inva <-- 1/(a-1);
    (a-1)*inva === 1;

    invb <-- 1/(b-1);
    (b-1)*invb === 1;

    c <== a*b;
}

component main = Multiplier(64);