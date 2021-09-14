#[macro_export]
macro_rules! impl_collection {
    ($coll_name:ident, $item_name: ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
        pub struct $coll_name<E: PairingEngine>(pub Vec<$item_name<E>>);

        impl<E: PairingEngine> $coll_name<E> {
            pub fn new() -> Self {
                Self(Vec::new())
            }

            pub fn add(&mut self, item: $item_name<E>) {
                self.0.push(item)
            }

            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }

            pub fn len(&self) -> usize {
                self.0.len()
            }
        }
    };
}
