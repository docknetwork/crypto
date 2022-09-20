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

include "./mimc_constants.circom";

template MiMC7(nrounds, constants) {
    signal input x_in;
    signal input k;
    signal output out;

    var t;
    signal t2[nrounds];
    signal t4[nrounds];
    signal t6[nrounds];
    signal t7[nrounds-1];

    for (var i=0; i<nrounds; i++) {
        t = (i==0) ? k+x_in : k + t7[i-1] + constants[i];
        t2[i] <== t*t;
        t4[i] <== t2[i]*t2[i];
        t6[i] <== t4[i]*t2[i];
        if (i<nrounds-1) {
            t7[i] <== t6[i]*t;
        } else {
            out <== t6[i]*t + k;
        }
    }
}

template MimcHash() {
    signal input in;
    signal input k;
    signal output out;

    component mimc = MiMC7(91, MIMC7_BLS12_381());
    mimc.x_in <== in;
    mimc.k <== k;
    out <== mimc.out;
}

component main = MimcHash();
