# Secret sharing and distributed key generation

Implements Secret Sharing (SS), Verifiable Secret Sharing (VSS), Distributed Verifiable Secret Sharing (DVSS) and Distributed 
Key Generation (DKG) algorithms. DVSS and DKG do not require a trusted dealer.

1. [Shamir secret sharing (Requires a trusted dealer)](./src/shamir_ss.rs)
1. [Pedersen Verifiable Secret Sharing](./src/pedersen_vss.rs)
1. [Pedersen Distributed Verifiable Secret Sharing](./src/pedersen_dvss.rs)
1. [Feldman Verifiable Secret Sharing](./src/feldman_vss.rs)
1. [Feldman Distributed Verifiable Secret Sharing](./src/feldman_dvss_dkg.rs)
1. [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](./src/gennaro_dkg.rs)
1. [Distributed Key Generation from FROST](./src/frost_dkg.rs)
1. [Distributed discrete log (DLOG) check](./src/distributed_dlog_check)