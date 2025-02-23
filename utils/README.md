<!-- cargo-rdme start -->

A collection of utilities used by our other libraries in this workspace.

- Pedersen commitment
- Elgamal encryption, including Hashed Elgamal
- finite field utilities like inner product, weighted inner product, hadamard product, etc.
- multiscalar multiplication (MSM) like Fixed Base MSM
- polynomial utilities like multiplying polynomials, creating polynomial from roots, etc.
- An efficient way to check several equality relations involving pairings by combining the relations in a random linear combination and doing a multi-pairing check. Relies on Schwartz–Zippel lemma.
- An efficient way to check several equality relations involving scalar multiplications by combining the relations in a random linear combination and doing a single multi-scalar multiplication check. Relies on Schwartz–Zippel lemma.
- hashing utilities like hashing arbitrary bytes to field element or group element.
- solving discrete log using Baby Step Giant Step algorithm

<!-- cargo-rdme end -->
