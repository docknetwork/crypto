/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/
pragma circom 2.0.0;

// `out` signal will contain the bits of input `in` with LSB in the beginning and MSB in end. `in` is expected to be
// of `n` bits at most.
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

// `out` signal will be set to 1 if `a < b` else 0.
template LessThan(n) {
    assert(n <= 252);
    signal input a;
    signal input b;
    signal output out;

    component n2b = Num2Bits(n+1);

    // 1<<n is the smallest n+1 bit number, if a < b, i.e. a-b < 0, MSB of (1<<n) + a - b will be 0 because of the borrow.
    // But if a > b, a-b > 0, even the largest a-b will be less than (1<<n), thus avoiding the carry and keeping the MSB of (1<<n) + a - b as 0

    n2b.in <== (1<<n) + a - b;
    out <== 1-n2b.out[n];
}

// N is the number of bits the input  have.
// The MSF is the sign bit.
template LessEqThan(n) {
    signal input a;
    signal input b;
    signal output out;

    component lt = LessThan(n);

    lt.a <== a;
    lt.b <== b+1;
    lt.out ==> out;
}

// N is the number of bits the input  have.
// The MSF is the sign bit.
template GreaterThan(n) {
    signal input a;
    signal input b;
    signal output out;

    component lt = LessThan(n);

    lt.a <== b;
    lt.b <== a;
    lt.out ==> out;
}

// N is the number of bits the input  have.
// The MSF is the sign bit.
template GreaterEqThan(n) {
    signal input a;
    signal input b;
    signal output out;

    component lt = LessThan(n);

    lt.a <== b;
    lt.b <== a+1;
    lt.out ==> out;
}

// `out` signal will be set to 1 if `in == 0` else 0.
template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0;

    out <== -in*inv +1;
    in*out === 0;
}

// `out` signal will be set to 1 if `a == b` else 0.
template IsEqual() {
    signal input a;
    signal input b;
    signal output out;

    component isz = IsZero();

    b - a ==> isz.in;

    isz.out ==> out;
}
