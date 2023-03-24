pragma circom 2.0.0;

// implements MiMC-2n/n as hash using a sponge construction.
// log_5(21888242871839275222246405745257275088548364400416034343698204186575808495617) ~= 110
// log_5(52435875175126190479447740508185965837690552500527637822603658699938581184513) ~= 110
// => nRounds should be 220
template MiMCSponge(nInputs, nRounds, nOutputs, constants) {
  signal input ins[nInputs];
  signal input k;
  signal output outs[nOutputs];

  var i;

  // S = R||C
  component S[nInputs + nOutputs - 1];

  for (i = 0; i < nInputs; i++) {
    S[i] = MiMCFeistel(nRounds, constants);
    S[i].k <== k;
    if (i == 0) {
      S[i].xL_in <== ins[0];
      S[i].xR_in <== 0;
    } else {
      S[i].xL_in <== S[i-1].xL_out + ins[i];
      S[i].xR_in <== S[i-1].xR_out;
    }
  }

  outs[0] <== S[nInputs - 1].xL_out;

  for (i = 0; i < nOutputs - 1; i++) {
    S[nInputs + i] = MiMCFeistel(nRounds, constants);
    S[nInputs + i].k <== k;
    S[nInputs + i].xL_in <== S[nInputs + i - 1].xL_out;
    S[nInputs + i].xR_in <== S[nInputs + i - 1].xR_out;
    outs[i + 1] <== S[nInputs + i].xL_out;
  }
}

template MiMCFeistel(nrounds, constants) {
    signal input xL_in;
    signal input xR_in;
    signal input k;
    signal output xL_out;
    signal output xR_out;

    var t;
    signal t2[nrounds];
    signal t4[nrounds];
    signal xL[nrounds-1];
    signal xR[nrounds-1];

    var c;
    for (var i=0; i<nrounds; i++) {
        if ((i == 0) || (i == nrounds - 1)) {
          c = 0;
        } else {
          c = constants[i - 1];
        }
        t = (i==0) ? k+xL_in : k + xL[i-1] + c;
        t2[i] <== t*t;
        t4[i] <== t2[i]*t2[i];
        if (i<nrounds-1) {
          var aux = (i==0) ? xR_in : xR[i-1] ;
          xL[i] <== aux + t4[i]*t;
          xR[i] <== (i==0) ? xL_in : xL[i-1];
        } else {
          xR_out <== xR[i-1] + t4[i]*t;
          xL_out <== xL[i-1];
        }
    }
}
