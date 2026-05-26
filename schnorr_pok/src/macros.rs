/// Verify a proof using either `RandomizedMultChecker` (batched verification) or direct
/// `verify` (individual verification).
///
/// For proof types with **2 owned-or-ref** arguments (e.g., `PokDiscreteLogProtocol`).
///
/// The first 2 args after `$proof` are the "switchable" arguments: passed by value to
/// `verify_using_randomized_mult_checker` and by reference to `verify`.
/// Remaining args are passed through unchanged (typically already references like `&challenge`).
#[macro_export]
macro_rules! verify_or_rmc_2 {
    ($rmc:expr, $proof:expr, $o1:expr, $o2:expr $(, $ref_arg:expr)* $(,)?) => {{
        match $rmc.as_mut() {
            Some(__rmc) => {
                $proof.verify_using_randomized_mult_checker($o1, $o2, $($ref_arg,)* __rmc);
                Ok(())
            }
            None => {
                $proof.verify(&$o1, &$o2, $($ref_arg,)*)
            }
        }
    }};
}

/// Same as [`verify_or_rmc_2`] but for proof types with **3 owned-or-ref** arguments
/// (e.g., `PokPedersenCommitmentProtocol`).
#[macro_export]
macro_rules! verify_or_rmc_3 {
    ($rmc:expr, $proof:expr, $o1:expr, $o2:expr, $o3:expr $(, $ref_arg:expr)* $(,)?) => {{
        match $rmc.as_mut() {
            Some(__rmc) => {
                $proof.verify_using_randomized_mult_checker($o1, $o2, $o3, $($ref_arg,)* __rmc);
                Ok(())
            }
            None => {
                $proof.verify(&$o1, &$o2, &$o3, $($ref_arg,)*)
            }
        }
    }};
}

/// Same as [`verify_or_rmc_2`] but for proof types with **4 owned-or-ref** arguments
/// (e.g., `PokDiscreteLogProtocol2`).
#[macro_export]
macro_rules! verify_or_rmc_4 {
    ($rmc:expr, $proof:expr, $o1:expr, $o2:expr, $o3:expr, $o4:expr $(, $ref_arg:expr)* $(,)?) => {{
        match $rmc.as_mut() {
            Some(__rmc) => {
                $proof.verify_using_randomized_mult_checker($o1, $o2, $o3, $o4, $($ref_arg,)* __rmc);
                Ok(())
            }
            None => {
                $proof.verify(&$o1, &$o2, &$o3, &$o4, $($ref_arg,)*)
            }
        }
    }};
}

/// Verify a [`SchnorrResponse`] using either `verify_using_randomized_mult_checker` or `is_valid`.
///
/// Both variants return `Result<()>` (propagated with `?`).
/// The bases, commitment point, and t-value are switchable between owned and ref.
#[macro_export]
macro_rules! verify_schnorr_resp_or_rmc {
    ($rmc:expr, $resp:expr, $bases:expr, $y:expr, $t:expr, $challenge:expr $(,)?) => {{
        match $rmc.as_mut() {
            Some(__rmc) => {
                $resp.verify_using_randomized_mult_checker($bases, $y, $t, $challenge, __rmc)
            }
            None => $resp.is_valid(&$bases, &$y, &$t, $challenge),
        }
    }};
}

/// Same as [`verify_partial_schnorr_resp_or_rmc!`] but for [`PartialSchnorrResponse`] which additionally
/// takes a `missing_resps` [`BTreeMap`] passed by value to both paths.
#[macro_export]
macro_rules! verify_partial_schnorr_resp_or_rmc {
    ($rmc:expr, $resp:expr, $bases:expr, $y:expr, $t:expr, $challenge:expr, $missing_resps:expr $(,)?) => {{
        match $rmc.as_mut() {
            Some(__rmc) => $resp.verify_using_randomized_mult_checker(
                $bases,
                $y,
                $t,
                $challenge,
                $missing_resps,
                __rmc,
            ),
            None => $resp.is_valid(&$bases, &$y, &$t, $challenge, $missing_resps),
        }
    }};
}

/// Verify a single pairing equation `e(a, b) = e(c, d)` using either
/// `RandomizedPairingChecker` (batched) or direct `multi_pairing` (immediate).
///
/// - `$E`: The pairing type (e.g., `Bls12_381`)
/// - `$pairing_checker`: `Option<&mut RandomizedPairingChecker<$E>>`
/// - `$a`: `&$E::G1Affine`
/// - `$b`: implements `Into<$E::G2Prepared>`
/// - `$c`: `&$E::G1Affine` (will be negated internally: checks e(a,b) = e(c,d) => e(a,b)*e(-c,d) = 0)
/// - `$d`: implements `Into<$E::G2Prepared>`
/// - `$err`: error expression returned on direct verification failure
///
/// Returns `Result<(), E>` where E is the error type of `$err`.
#[macro_export]
macro_rules! verify_pairing_or_rmc {
    ($E:ty, $pairing_checker:expr, $a:expr, $b:expr, $c:expr, $d:expr, $err:expr $(,)?) => {{
        match $pairing_checker.as_mut() {
            Some(__pc) => {
                __pc.add_sources($a, $b, $c, $d);
                Ok(())
            }
            None => {
                let neg_c: <$E as ark_ec::pairing::Pairing>::G1Affine =
                    (-(<$E as ark_ec::pairing::Pairing>::G1::from(*$c))).into();
                if !<$E as ark_ec::pairing::Pairing>::multi_pairing(
                    [
                        <$E as ark_ec::pairing::Pairing>::G1Prepared::from(*$a),
                        <$E as ark_ec::pairing::Pairing>::G1Prepared::from(neg_c),
                    ],
                    [$b, $d],
                )
                .is_zero()
                {
                    Err($err)
                } else {
                    Ok(())
                }
            }
        }
    }};
}

/// Verify multiple pairing product equation `∏e(a_i, b_i) = out` using either
/// `RandomizedPairingChecker` (batched) or direct `multi_pairing` (immediate).
///
/// - `$E`: The pairing type (e.g., `Bls12_381`)
/// - `$pairing_checker`: `Option<&mut RandomizedPairingChecker<$E>>`
/// - `$a`: `&[$E::G1Affine]`
/// - `$b`: implements `IntoIterator<Item = impl Into<$E::G2Prepared>>`
/// - `$out`: `&ark_ec::pairing::PairingOutput<$E>`
/// - `$err`: error expression returned on direct verification failure
///
/// Returns `Result<(), E>` where E is the error type of `$err`.
#[macro_export]
macro_rules! verify_multiple_pairings_and_target_or_rmc {
    ($E:ty, $pairing_checker:expr, $a:expr, $b:expr, $out:expr, $err:expr $(,)?) => {{
        match $pairing_checker.as_mut() {
            Some(__pc) => {
                __pc.add_multiple_sources_and_target($a, $b, $out);
                Ok(())
            }
            None => {
                if <$E as ark_ec::pairing::Pairing>::multi_pairing($a, $b) != *$out {
                    Err($err)
                } else {
                    Ok(())
                }
            }
        }
    }};
}
