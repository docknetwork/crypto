pragma circom 2.0.0;

include "difference_of_array_sum.circom";

// Check if difference of sum of 20 inputs signals and sum of 20 other inputs signals is more than the public signal `max`. Each input signal must be of size at most 64 bits.
component main {public [min]} = DifferenceOfArraySum(20, 20, 64);
