pragma circom 2.0.0;

include "set_membership.circom";

// Set membership in a set of size 5
component main {public [set]} = SetMembership(5);