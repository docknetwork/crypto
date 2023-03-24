pragma circom 2.0.0;

include "sum_less_than.circom";

// Check if sum of input array of size 12 is less than the public signal `max`. Each input signal must be of size at most 64 bits.
component main {public [max]} = SumLessThan(12, 64);