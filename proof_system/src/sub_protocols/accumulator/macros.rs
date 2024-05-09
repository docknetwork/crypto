macro_rules! impl_common_funcs {
    ( $prepared_params_type: ident, $prepared_pk_type: ident, $wit_type: ident, $wit_group: path, $wit_protocol:ident, $proof_enum_variant: ident, $proof_typ: ident, $error_typ: ident) => {
        pub fn init<R: RngCore>(
            &mut self,
            rng: &mut R,
            blinding: Option<E::ScalarField>,
            witness: crate::witness::$wit_type<$wit_group>,
        ) -> Result<(), ProofSystemError> {
            if self.protocol.is_some() {
                return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
            }
            let protocol = $wit_protocol::init(
                rng,
                witness.element,
                blinding,
                &witness.witness,
                self.public_key,
                self.params,
                self.proving_key,
            );
            self.protocol = Some(protocol);
            Ok(())
        }

        pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
            if self.protocol.is_none() {
                return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                    self.id,
                ));
            }
            self.protocol.as_ref().unwrap().challenge_contribution(
                &self.accumulator_value,
                self.public_key,
                self.params,
                self.proving_key,
                writer,
            )?;
            Ok(())
        }

        pub fn gen_proof_contribution(
            &mut self,
            challenge: &E::ScalarField,
        ) -> Result<StatementProof<E>, ProofSystemError> {
            if self.protocol.is_none() {
                return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                    self.id,
                ));
            }
            let protocol = self.protocol.take().unwrap();
            let proof = protocol.gen_proof(challenge)?;
            Ok(StatementProof::$proof_enum_variant(proof))
        }

        pub fn verify_proof_contribution(
            &self,
            challenge: &E::ScalarField,
            proof: &$proof_typ<E>,
            pk: impl Into<$prepared_pk_type<E>>,
            params: impl Into<$prepared_params_type<E>>,
            pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
        ) -> Result<(), ProofSystemError> {
            match pairing_checker {
                Some(c) => proof.verify_with_randomized_pairing_checker(
                    &self.accumulator_value,
                    challenge,
                    pk,
                    params,
                    self.proving_key,
                    c,
                ),
                None => proof.verify(
                    &self.accumulator_value,
                    challenge,
                    pk,
                    params,
                    self.proving_key,
                ),
            }
            .map_err(|e| ProofSystemError::$error_typ(self.id as u32, e))
        }
    };
}

macro_rules! impl_struct_and_funcs {
    ($(#[$doc:meta])*
    $name: ident, $param_type: ident, $pk_type: ident, $prepared_params_type: ident, $prepared_pk_type: ident, $prk_type: ident, $protocol: ident, $wit_type: ident, $wit_group: path, $proof_enum_variant: ident, $proof_typ: ident, $error_typ: ident) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name<'a, E: Pairing> {
            pub id: usize,
            pub params: &'a $param_type<E>,
            pub public_key: &'a $pk_type<E>,
            pub proving_key: &'a $prk_type<E::G1Affine>,
            pub accumulator_value: E::G1Affine,
            pub protocol: Option<$protocol<E>>,
        }

        impl<'a, E: Pairing> $name<'a, E> {
            pub fn new(
                id: usize,
                params: &'a $param_type<E>,
                public_key: &'a $pk_type<E>,
                proving_key: &'a $prk_type<E::G1Affine>,
                accumulator_value: E::G1Affine,
            ) -> Self {
                Self {
                    id,
                    params,
                    public_key,
                    proving_key,
                    accumulator_value,
                    protocol: None,
                }
            }

            impl_common_funcs!(
                $prepared_params_type,
                $prepared_pk_type,
                $wit_type,
                $wit_group,
                $protocol,
                $proof_enum_variant,
                $proof_typ,
                $error_typ
            );
        }
    };
}
