# Secret sharing and distributed key generation

Implements Secret Sharing (SS), Verifiable Secret Sharing (VSS), Distributed Verifiable Secret Sharing (DVSS) and Distributed 
Key Generation (DKG) algorithms. DVSS and DKG do not require a trusted dealer.

1. [Shamir secret sharing (Requires a trusted dealer)](src/shamir_ss.rs)
1. [Pedersen Verifiable Secret Sharing](src/pedersen_vss.rs)
1. [Pedersen Distributed Verifiable Secret Sharing](src/pedersen_dvss.rs)
1. [Feldman Verifiable Secret Sharing](src/feldman_vss.rs)
1. [Feldman Distributed Verifiable Secret Sharing](src/feldman_dvss_dkg.rs)
1. [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](src/gennaro_dkg.rs)
1. [Distributed Key Generation from FROST](src/frost_dkg.rs)

**Note: This is largely a reimplementation of [secret-sharing-schemes](https://github.com/lovesh/secret-sharing-schemes) but 
based on arkworks-rs with some change in the API. Moreover, implements the Gennaro DKG and FROST's DKG**