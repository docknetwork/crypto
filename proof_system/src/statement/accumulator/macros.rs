macro_rules! impl_pk_and_param_getters {
    ($param_type: ident, $param_variant: ident, $pk_type: ident, $pk_variant: ident) => {
        /// Get accumulator params for the statement index `s_idx` either from `self` or from given `setup_params`
        pub fn get_params<'a>(
            &'a self,
            setup_params: &'a [SetupParams<E>],
            st_idx: usize,
        ) -> Result<&'a $param_type<E>, ProofSystemError> {
            extract_param!(
                setup_params,
                &self.params,
                self.params_ref,
                $param_variant,
                IncompatibleAccumulatorSetupParamAtIndex,
                st_idx
            )
        }

        /// Get public key for the statement index `s_idx` either from `self` or from given `setup_params`
        pub fn get_public_key<'a>(
            &'a self,
            setup_params: &'a [SetupParams<E>],
            st_idx: usize,
        ) -> Result<&'a $pk_type<E>, ProofSystemError> {
            extract_param!(
                setup_params,
                &self.public_key,
                self.public_key_ref,
                $pk_variant,
                IncompatibleAccumulatorSetupParamAtIndex,
                st_idx
            )
        }
    };
}

macro_rules! impl_getters {
    ( $param_type: ident, $param_variant: ident, $pk_type: ident, $pk_variant: ident, $prk_type:ident, $prk_variant:ident) => {
        impl_pk_and_param_getters!($param_type, $param_variant, $pk_type, $pk_variant);

        /// Get membership proving key for the statement index `s_idx` either from `self` or from given `setup_params`
        pub fn get_proving_key<'a>(
            &'a self,
            setup_params: &'a [SetupParams<E>],
            st_idx: usize,
        ) -> Result<&'a $prk_type<E::G1Affine>, ProofSystemError> {
            extract_param!(
                setup_params,
                &self.proving_key,
                self.proving_key_ref,
                $prk_variant,
                IncompatibleAccumulatorSetupParamAtIndex,
                st_idx
            )
        }
    };
}

macro_rules! impl_struct_and_funcs {
    ($(#[$doc:meta])*
    $name:ident, $param_type: ident, $param_variant: ident, $pk_type: ident, $pk_variant: ident, $statement_variant:ident, $prk_type:ident, $prk_variant:ident) => {
        #[serde_as]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        #[serde(bound = "")]
        pub struct $name<E: Pairing> {
            #[serde_as(as = "ArkObjectBytes")]
            pub accumulator_value: E::G1Affine,
            pub params: Option<$param_type<E>>,
            pub public_key: Option<$pk_type<E>>,
            pub proving_key: Option<$prk_type<E::G1Affine>>,
            pub params_ref: Option<usize>,
            pub public_key_ref: Option<usize>,
            pub proving_key_ref: Option<usize>,
        }

        impl<E: Pairing> $name<E> {
            /// Create a statement by passing the accumulator params, public key and proving key directly.
            pub fn new_statement_from_params(
                params: $param_type<E>,
                public_key: $pk_type<E>,
                proving_key: $prk_type<E::G1Affine>,
                accumulator_value: E::G1Affine,
            ) -> Statement<E> {
                Statement::$statement_variant(Self {
                    accumulator_value,
                    params: Some(params),
                    public_key: Some(public_key),
                    proving_key: Some(proving_key),
                    params_ref: None,
                    public_key_ref: None,
                    proving_key_ref: None,
                })
            }

            /// Create a statement by passing the indices of accumulator params, public key and proving key in `SetupParams`.
            pub fn new_statement_from_params_ref(
                params_ref: usize,
                public_key_ref: usize,
                proving_key_ref: usize,
                accumulator_value: E::G1Affine,
            ) -> Statement<E> {
                Statement::$statement_variant(Self {
                    accumulator_value,
                    params: None,
                    public_key: None,
                    proving_key: None,
                    params_ref: Some(params_ref),
                    public_key_ref: Some(public_key_ref),
                    proving_key_ref: Some(proving_key_ref),
                })
            }

            impl_getters!(
                $param_type,
                $param_variant,
                $pk_type,
                $pk_variant,
                $prk_type,
                $prk_variant
            );
        }
    };
}
