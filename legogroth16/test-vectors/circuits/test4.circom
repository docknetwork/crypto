pragma circom 2.0.0;

/*This circuit template checks that
z1 = a*x + b*y + 10*p*q - 19*r^3*p + 55*s^4*q^3 - 3*x^2 + 6*x*y - 13*y^3 - r*s*x + 5*a*b*y - 32*a*x*y - 2*x*y*p*q - 100
z2 = a^3*y + 3b^2*x - 20*x^2*y^2 + 45
*/

template Test4 () {
    // Declaration of signals.
    signal input x;
    signal input y;
    signal input p;
    signal input q;
    signal input a;
    signal input b;
    signal input r;
    signal input s;

    signal output z1;
    signal output z2;

    // Constraints.
    signal ax <== a * x;
    signal by <== b * y;
    signal t1 <== 10 * p * q;
    signal t2 <== -19 * p * r;
    signal r_sqr <== r * r;
    signal t3 <== t2 * r_sqr;
    signal s_sqr <== s * s;
    signal s_4 <== s_sqr * s_sqr;
    signal q_sqr <== q * q;
    signal q_cube <== q_sqr * q;
    signal t4 <== 55 * s_4 * q_cube;
    signal t5 <== -3 * x * x;
    signal t6 <== 6 * x * y;
    signal y_sqr <== y * y;
    signal t7 <== -13 * y * y_sqr;
    signal rs <== r * s;
    signal t8 <== -rs * x;

    // Following 2 can be written as 1 constraint as 5 * a * by
    signal t9 <== 5 * a * b;
    signal t10 <== t9 * y;

    // Following 2 can be written as 1 constraint as -32 * ax * y
    signal t11 <== -32 * a * x;
    signal t12 <== t11 * y;

    signal t13 <== - 2 * x * y;
    signal t14 <== p * q;
    signal t15 <== t13 * t14;

    signal a_sqr <== a * a;
    signal a_cube <== a_sqr * a;
    signal t16 <== a_cube * y;
    signal b_sqr <== b * b;
    signal t17 <== 3 * b_sqr * x;
    signal x_sqr <== x * x;
    signal t18 <== -20 * x_sqr * y_sqr;


    z1 <== ax + by + t1 + t3 + t4 + t5 + t6 + t7 + t8 + t10 + t12 + t15 - 100;
    z2 <== t16 + t17 + t18 + 45;
}

component main {public [a, b, r, s]} = Test4();