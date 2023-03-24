# Snarckpack for both Groth16 and LegoGroth16

Aggregating multiple zk-SNARK proofs using [Snarckpack](https://eprint.iacr.org/2021/529). Implementation modified from https://github.com/nikkolasg/snarkpack

TODO: When creating aggregate proof over multiple Groth16 and LegoGroth16 on same or different circuits, TIPP-MIPP step needs 
to be done for each (Lego)Groth16 SRS but the KZG proof for `v` and `w` must only be created once.