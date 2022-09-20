pragma circom 2.0.0;

/*This circuit template checks that the given 2 inputs are 32 bit numbers and the 1st input is less than 2nd input */

include "comparators.circom";

component main = LessThan(32);