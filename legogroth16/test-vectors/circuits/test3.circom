pragma circom 2.0.0;

/*This circuit template checks that
z1 = a*x + b*y + c*d
z2 = c*x + d*y
*/

template Test3 () {
    // Declaration of signals.
    signal input x;
    signal input y;
    signal input a;
    signal input b;
    signal input c;
    signal input d;

    signal output z1;
    signal output z2;

    // Constraints.
    signal ax <== a * x;
    signal by <== b * y;
    signal cd <== c * d;
    signal cx <== c * x;
    signal dy <== d * y;

    z1 <== ax + by + cd;
    z2 <== cx + dy;
}

component main {public [x, y]} = Test3();