# Composite proof system

<!-- cargo-rdme start -->

The goal of this crate is to allow creating and combining zero knowledge proofs by executing several
protocols as sub-protocols.

The idea is to represent each relation to be proved as a [`Statement`], and any relations between
[`Statement`]s as a [`MetaStatement`]. Both of these types contain public (known to both prover
and verifier) information and are contained in a [`ProofSpec`] whose goal is to unambiguously
define what needs to be proven. Some [`Statement`]s are specific to either the prover or the verifier
as those protocols require prover and verifier to use different public parameters. An example is Groth16
based SNARK protocols where the prover needs to have a proving key and the verifier needs to
have a verifying key. Both the prover and verifier can know both the proving and verifying key but
they don't need to. Thus for such protocols, there are different [`Statement`]s for prover and verifier,
like [`SaverProver`] and [`SaverVerifier`] are statements for prover and verifier respectively,
executing SAVER protocol.

Several [`Statement`]s might need same public parameters like proving knowledge of several BBS+
from the same signer, or verifiable encryption of several messages for the same decryptor. Its not
very efficient to pass the same parameters to each [`Statement`] especially when using this code's WASM
bindings as the same values will be serialized and deserialized every time. To avoid this, caller can
put all such public parameters as [`SetupParams`] in an array and then reference those by their index
while creating an [`Statement`]. This array of [`SetupParams`] is then included in the [`ProofSpec`]
and used by the prover and verifier during proof creation and verification respectively.

A common requirement is to prove equality of certain [`Witness`]s of certain [`Statement`]s. This
is done by using the [`EqualWitnesses`] meta-statement. For each set of [`Witness`]s (from the same or different [`Statement`]s)
that need to proven equal, a [`EqualWitnesses`] is created which is a set of witness references [`WitnessRef`].
Each [`WitnessRef`] contains the [`Statement`] index and the [`Witness`] index in that [`Statement`] and
thus uniquely identifies any [`Witness`] across [`Statement`]s. The [`EqualWitnesses`] meta-statement is also
used to prove predicates over signed messages in zero knowledge, when doing a range-proof over a
signed message (using BBS+), the [`EqualWitnesses`] will refer [`Witness`]s from `Statement::PoKBBSSignatureG1`
statement and `Statement::BoundCheckLegoGroth16` statement. Following are some illustrations of [`EqualWitnesses`]

```text
 ┌────────────────────────────┐    ┌──────────────────────────────┐     ┌────────────────────────────┐
 │ PokBBSSignatureG1          │    │ PokBBSSignatureG1            │     │ PokBBSSignatureG1          │
 │ Statement 1                │    │ Statement 2                  │     │ Statement 3                │
 ├────────────────────────────┤    ├──────────────────────────────┤     ├────────────────────────────┤
 │ A1, A2, A3, A4, A5         │    │ B1, B2, B3, B4               │     │ C1, C2, C3, C4, C5, C6     │
 └─────────▲──────────────────┘    └─────▲────────▲───────────────┘     └─▲────────────────▲─────────┘
           │                             │        │                       │                │
           │                             │        │                       │                │
           │                             │        │                       │                │
           │                             │        │                       │                │
           │            ┌-───────────────┴────────┴───┬───────────────────┼──────┬─────────┴──────────────────┐
           └────────────┼(0, 2), (1, 1), (2, 0)       ├───────────────────┘      │ (2, 3), (3, 4)             │
                        ├-────────────────────────────┤                          ├────────────────────────────┤
                        │       EqualWitnesses        │                          │  EqualWitnesses            │
                        │       MetaStatement 1       │                          │  MetaStatement 2           │
                        │ A3, B2 and C1 are equal     │                          │  B4 and C5 are equal       │
                        └─────────────────────────────┘                          └────────────────────────────┘
```

```
   For proving certain messages from 3 BBS+ signatures are equal. Here there 2 sets of equalities,
   1. message A3 from 1st signature, B2 from 2nd signature and C1 from 3rd signature
   2. message B4 from 2nd signature and C5 from 3rd signature

   Thus 3 statements, one for each signature, and 2 meta statements, one for each equality
```
---------------------------------------------------------------------------------------------------------------------------------------------------
```text
 ┌────────────────────────────┐    ┌──────────────────────────────┐     ┌────────────────────────────┐
 │ PokBBSSignatureG1          │    │ BoundCheckLegoGroth16        │     │ SAVER                      │
 │ Statement 1                │    │ Statement 2                  │     │ Statement 3                │
 ├────────────────────────────┤    ├──────────────────────────────┤     ├────────────────────────────┤
 │ A1, A2, A3, A4, A5         │    │     B1                       │     │             C1             │
 └─────────▲───────▲──────────┘    └─────▲────────-───────────────┘     └───────────────▲────-───────┘
           │       |─────────────────|   │                                              │
           │                         |   │                                              │
           │                         |──-│-────────────────────|                        │
           │                             │                     |                        |───|
           │            ┌-───────────────┴────────-───┬────────|───────────────────────────-|─────────────────┐
           └────────────┼(0, 2),  (1, 0)              |        |─────────────────│── (0, 4), (2, 1)           │
                        ├-────────────────────────────┤                          ├────────────────────────────┤
                        │       EqualWitnesses        │                          │  EqualWitnesses            │
                        │       MetaStatement 1       │                          │  MetaStatement 2           │
                        │ A3 and  B1 are equal        │                          │  A5 and C1 are equal       │
                        └─────────────────────────────┘                          └────────────────────────────┘
```

```
   For proving certain messages from a BBS+ signature satisfy 2 predicates,
    1) message A3 satisfies bounds specified in statement 2
    2) message A5 has been verifiably encrypted as per statement 3.

  Thus 3 statements, one for a signature, and one each for a predicate. 2 meta statements, one each
  for proving equality of the message of the signature and the witness of the predicate
```
--------------------------------------------------------------------------------------------------------------------------------

After creating the [`ProofSpec`], the prover uses a [`Witness`] per [`Statement`] and creates a
corresponding [`StatementProof`]. All [`StatementProof`]s are grouped together in a [`Proof`].
The verifier also creates its [`ProofSpec`] and uses it to verify the given proof. Currently it is
assumed that there is one [`StatementProof`] per [`Statement`] and one [`Witness`] per [`Statement`]
and [`StatementProof`]s appear in the same order in [`Proof`] as [`Statement`]s do in [`ProofSpec`].

[`Statement`], [`Witness`] and [`StatementProof`] are enums whose variants will be entities from different
protocols. Each of these protocols are variants of the enum [`SubProtocol`]. [`SubProtocol`]s can internally
call other [`SubProtocol`]s, eg [`SaverProtocol`] invokes several [`SchnorrProtocol`]s

Currently supports
- proof of knowledge of a BBS or BBS+ signature and signed messages
- proof of knowledge of multiple BBS or BBS+ signature and equality of certain messages
- proof of knowledge of accumulator membership and non-membership
- proof of knowledge of Pedersen commitment opening.
- proof of knowledge of BBS or BBS+ signature(s) and that certain message(s) satisfy given bounds (range proof)
- verifiable encryption of messages in a BBS or BBS+ signature
- proof of knowledge of BBS or BBS+ signature(s) and that certain message(s) satisfy given R1CS. The R1CS is generated
  from [Circom](https://github.com/iden3/circom) and the proof system used is [LegoGroth16](https://github.com/lovesh/legogro16).
  LegoGroth16 is similar to Groth16 but in addition to the zero knowledge proof, it provides a Pedersen
  commitment to the witness (signed messages in our case). This commitment allows us to prove that the witness in
  the proof protocol are the same as the signed messages using the Schnorr proof of knowledge protocol.

See following tests for examples:

- test `pok_of_3_bbs_plus_sig_and_message_equality` proves knowledge of 3 BBS+ signatures and also that certain
  messages are equal among them without revealing them.
- test `pok_of_bbs_plus_sig_and_accumulator` proves knowledge of a BBS+ signature and also that certain messages
  are present and absent in the 2 accumulators respectively.
- test `pok_of_knowledge_in_pedersen_commitment_and_bbs_plus_sig` proves knowledge of a BBS+ signature and opening
  of a Pedersen commitment.
- test `requesting_partially_blind_bbs_plus_sig` shows how to request a blind BBS+ signature by proving opening of
  a Pedersen commitment.
- test `verifier_local_linkability` shows how a verifier can link separate proofs from a prover (with prover's
  permission) and assign a unique identifier to the prover without learning any message from the BBS+ signature.
  Also this identifier cannot be linked across different verifiers (intentional by the prover).
- test `pok_of_bbs_plus_sig_and_bounded_message` shows proving knowledge of a BBS+ signature and that a specific
  message satisfies some upper and lower bounds i.e. min <= signed message <= max. This is a range proof.
- test `pok_of_bbs_plus_sig_and_verifiable_encryption` shows how to verifiably encrypt a message signed with BBS+ such
  that the verifier cannot decrypt it but still ensure that it is encrypted correctly for the specified decryptor.
- test `pok_of_bbs_plus_sig_with_reusing_setup_params` shows proving knowledge of several BBS+ signatures
  using [`SetupParams`]s. Here the same signers are used in multiple signatures thus their public params
  can be put as a variant of enum [`SetupParams`]. Similarly test
  `pok_of_knowledge_in_pedersen_commitment_and_equality_with_commitment_key_reuse` shows use of [`SetupParams`]
  when the same commitment key is reused in several commitments and test `pok_of_bbs_plus_sig_and_verifiable_encryption_of_many_messages`
  shows use of [`SetupParams`] when several messages are used in verifiable encryption for the same decryptor.
- For R1CS/Circom, see various tests like using less than, not-equals comparison operators on messages signed with BBS+, proving
  that the preimage of an MiMC hash is the message signed with BBS+, sum of certain signed messages (from same or different signatures)
  is bounded by a given value, etc [here](tests/r1cs). The Circom compiler output and circuits are [here](tests/r1cs/circom).
  The circuits were compiled and tested for BLS12-381 curve.

*Note*: This design is largely inspired from my work at Hyperledger Ursa.

*Note*: The design is tentative and will likely change as more protocols are integrated.

[`Statement`]: https://docs.rs/proof_system/latest/proof_system/statement/enum.Statement.html
[`MetaStatement`]: https://docs.rs/proof_system/latest/proof_system/meta_statement/enum.MetaStatement.html
[`EqualWitnesses`]: https://docs.rs/proof_system/latest/proof_system/meta_statement/struct.EqualWitnesses.html
[`WitnessRef`]: https://docs.rs/proof_system/latest/proof_system/meta_statement/type.WitnessRef.html
[`SaverProver`]: https://docs.rs/proof_system/latest/proof_system/statement/saver/struct.SaverProver.html
[`SaverVerifier`]: https://docs.rs/proof_system/latest/proof_system/statement/saver/struct.SaverVerifier.html
[`SetupParams`]: https://docs.rs/proof_system/latest/proof_system/setup_params/enum.SetupParams.html
[`ProofSpec`]: https://docs.rs/proof_system/latest/proof_system/proof_spec/struct.ProofSpec.html
[`Witness`]: https://docs.rs/proof_system/latest/proof_system/witness/enum.Witness.html
[`StatementProof`]: https://docs.rs/proof_system/latest/proof_system/statement_proof/enum.StatementProof.html
[`Proof`]: proof::Proof
[`SubProtocol`]: https://docs.rs/proof_system/latest/proof_system/sub_protocols/enum.SubProtocol.html
[`SaverProtocol`]: https://docs.rs/proof_system/latest/proof_system/sub_protocols/saver/struct.SaverProtocol.html
[`SchnorrProtocol`]: https://docs.rs/proof_system/latest/proof_system/sub_protocols/schnorr/struct.SchnorrProtocol.html

<!-- cargo-rdme end -->
