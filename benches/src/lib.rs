#[macro_export]
macro_rules! setup_bbs_plus {
    ($sig_params:ident, $keypair: ident, $rng: ident, $message_count_range: ident, $messages_range: ident, $params_range: ident, $keypair_range: ident) => {
        // Hardcoding multi-message sizes. This should ideally be taken/updated from command line input
        let $message_count_range = [2, 4, 8, 15, 20, 30, 40, 60];
        let $messages_range = $message_count_range
            .iter()
            .map(|c| {
                (0..*c)
                    .into_iter()
                    .map(|_| Fr::rand(&mut $rng))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let $params_range = $message_count_range
            .iter()
            .map(|c| $sig_params::<Bls12_381>::generate_using_rng(&mut $rng, *c))
            .collect::<Vec<_>>();
        let $keypair_range = $params_range
            .iter()
            .map(|p| $keypair::<Bls12_381>::generate(&mut $rng, p))
            .collect::<Vec<_>>();
    };
}

pub mod accumulators;
