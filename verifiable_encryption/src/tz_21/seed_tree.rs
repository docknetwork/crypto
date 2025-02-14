//! Binary tree to create a large number of random values (deterministically) from a single random seed.
//! Taken largely from [here](https://github.com/akiratk0355/verenc-mpcith/blob/main/dkgith/src/seed_tree.rs).

use crate::error::VerifiableEncryptionError;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec, vec::Vec};
use digest::{ExtendableOutput, Update, XofReader};
use dock_crypto_utils::{aliases::FullDigest, hashing_utils::hash_to_field};
use zeroize::Zeroize;

pub const DEFAULT_SEED_SIZE: usize = 16;
pub const DEFAULT_SALT_SIZE: usize = 32;

/// Type of a node of the tree.
pub type Seed<const SEED_SIZE: usize = DEFAULT_SEED_SIZE> = [u8; SEED_SIZE];

/// A path of the tree from leaf to top (excluding root node) that lets you create the whole tree
/// except a particular leaf. Its length should be the depth of the tree.
pub type TreeOpening<const SEED_SIZE: usize = DEFAULT_SEED_SIZE> = Vec<Seed<SEED_SIZE>>;

/// A binary merkle tree of `NUM_LEAVES` number of leaf nodes. `NUM_LEAVES` is expected to be a power of 2
/// such that we have a full binary tree. Compile time check ensure this constraint.
/// This is created by selecting a random root node seed, then hashing it to create 2 children, each of which is
/// hashed again to create 2 children and so on until the tree has `NUM_LEAVES` leaves.
/// The tree is represented as an array of nodes where the 0th index of array is the root node,
/// next `NUM_LEAVES` - 2 indices are for internal nodes and last `NUM_LEAVES` indices are for leaf nodes.
/// The tree has `2*NUM_LEAVES - 1` nodes in total and its depth is `log_2(NUM_LEAVES)`
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct SeedTree<const NUM_LEAVES: usize, const SEED_SIZE: usize = DEFAULT_SEED_SIZE>(
    pub Vec<Seed<SEED_SIZE>>,
);

impl<const NUM_LEAVES: usize, const SEED_SIZE: usize> Default for SeedTree<NUM_LEAVES, SEED_SIZE> {
    fn default() -> Self {
        let nodes = vec![[0; SEED_SIZE]; NUM_LEAVES];
        Self(nodes)
    }
}

impl<const NUM_LEAVES: usize, const SEED_SIZE: usize> SeedTree<NUM_LEAVES, SEED_SIZE> {
    const CHECK_LEAF_COUNT: () = assert!(NUM_LEAVES.is_power_of_two());

    /// Create a new tree.
    pub fn create<R: RngCore, D: Default + Update + ExtendableOutput>(
        rng: &mut R,
        salt: &[u8],
        rep_index: usize,
    ) -> Self {
        let root_seed = Self::random_seed(rng);
        Self::create_given_root_node::<D>(root_seed, salt, rep_index)
    }

    /// Given a root node, generate rest of nodes deterministically.
    pub fn create_given_root_node<D: Default + Update + ExtendableOutput>(
        root_seed: Seed<SEED_SIZE>,
        salt: &[u8],
        rep_index: usize,
    ) -> Self {
        let _ = Self::CHECK_LEAF_COUNT;
        let mut nodes = vec![Self::zero_seed(); Self::num_total_nodes() as usize];
        nodes[0] = root_seed;
        let rep_index = rep_index as u16;

        for i in 0..(NUM_LEAVES as u16) - 1 {
            // Create 2 children of node at index [i] and set the left and right child nodes to them
            let (left, right) = Self::expand::<D>(&nodes[i as usize], salt, rep_index, i);
            nodes[Self::left_child_index(i) as usize] = left;
            nodes[Self::right_child_index(i) as usize] = right;
        }

        SeedTree(nodes)
    }

    #[inline(always)]
    pub fn get_leaf(&self, leaf_index: u16) -> Seed<SEED_SIZE> {
        assert!(
            (leaf_index as usize) < NUM_LEAVES,
            "get_leaf: leaf index too large"
        );
        // First NUM_LEAVES - 1 of nodes are the root and internal nodes
        self.0[NUM_LEAVES - 1 + leaf_index as usize]
    }

    /// Return the leaf of the tree but as a finite field element.
    // In the referred implementation, salt and rep_index are added too, but they don't need to be added
    // as they are already added when creating the tree
    pub fn get_leaf_as_finite_field_element<F: PrimeField, D: FullDigest>(
        &self,
        leaf_index: u16,
        domain_separator: &[u8],
    ) -> F {
        let leaf = self.get_leaf(leaf_index);
        let mut bytes = vec![];
        leaf.serialize_compressed(&mut bytes).unwrap();
        leaf_index.serialize_compressed(&mut bytes).unwrap();
        hash_to_field::<F, D>(domain_separator, &bytes)
    }

    /// Return nodes on a path from leaf level till root level - 1 (excluding root node as root node can create the whole tree)
    /// that allow reconstructing all leaves at indices except `unopened_leaf_index`
    pub fn open_seeds(&self, unopened_leaf_index: u16) -> TreeOpening<SEED_SIZE> {
        assert!(unopened_leaf_index < NUM_LEAVES as u16);
        let mut current = unopened_leaf_index + Self::num_non_leaf_nodes();
        let mut path = vec![Self::zero_seed(); Self::depth() as usize];
        // Go from bottom to top of the tree but don't add root node in the path.
        // At each level, grab the sibling of the current node
        for i in 0..path.len() {
            let sibling = Self::sibling_index(current);
            debug_assert_ne!(sibling, 0);
            path[i] = self.0[sibling as usize];
            current = Self::parent_index(current);
        }
        path
    }

    /// Given a `TreeOpening`, create all the nodes of the tree except the leaf at `unopened_leaf_index`
    pub fn reconstruct_tree<D: Default + Update + ExtendableOutput>(
        unopened_leaf_index: u16,
        tree_opening: &TreeOpening<SEED_SIZE>,
        salt: &[u8],
        rep_index: usize,
    ) -> Result<Self, VerifiableEncryptionError> {
        let _ = Self::CHECK_LEAF_COUNT;
        if tree_opening.len() != Self::depth() as usize {
            return Err(VerifiableEncryptionError::UnexpectedTreeOpeningSize(
                tree_opening.len(),
                Self::depth() as usize,
            ));
        }

        let mut unopened_node_index = unopened_leaf_index + Self::num_non_leaf_nodes();
        let mut nodes = vec![Self::zero_seed(); Self::num_total_nodes() as usize];

        // From bottom to top, set sibling nodes on the path of the unopened leaf
        for i in 0..Self::depth() as usize {
            nodes[Self::sibling_index(unopened_node_index) as usize] = tree_opening[i];
            unopened_node_index = Self::parent_index(unopened_node_index);
        }
        let zero_seed = Self::zero_seed();
        // root and unopened leaf node wouldn't be set
        debug_assert_eq!(nodes[0], zero_seed);
        debug_assert_eq!(nodes[unopened_node_index as usize], zero_seed);

        // Iterate over all the non-leaf nodes except root node on the path to the leaf at `unopened_leaf_index`
        // to eventually set the leaves except the leaf at `unopened_leaf_index`
        for i in 1..Self::num_non_leaf_nodes() {
            if nodes[i as usize] != zero_seed {
                let (left, right) =
                    Self::expand::<D>(&nodes[i as usize], salt, rep_index as u16, i);
                nodes[Self::left_child_index(i) as usize] = left;
                nodes[Self::right_child_index(i) as usize] = right;
            }
        }
        // root and unopened leaf node wouldn't be set
        debug_assert_eq!(nodes[0], zero_seed);
        debug_assert_eq!(nodes[unopened_node_index as usize], zero_seed);

        Ok(Self(nodes))
    }

    /// Given a parent node, create its 2 children nodes
    fn expand<D: Default + Update + ExtendableOutput>(
        node: &Seed<SEED_SIZE>,
        salt: &[u8],
        rep_index: u16,
        node_index: u16,
    ) -> (Seed<SEED_SIZE>, Seed<SEED_SIZE>) {
        let mut hasher = D::default();
        Update::update(&mut hasher, &salt);
        Update::update(&mut hasher, &rep_index.to_le_bytes());
        Update::update(&mut hasher, &node_index.to_le_bytes());
        Update::update(&mut hasher, node);
        let mut reader = hasher.finalize_xof();
        let mut left = [0u8; SEED_SIZE];
        let mut right = [0u8; SEED_SIZE];
        reader.read(&mut left);
        reader.read(&mut right);
        (left, right)
    }

    /// Total nodes including root, leaf and non-leaf nodes
    pub const fn num_total_nodes() -> u16 {
        2 * (NUM_LEAVES as u16) - 1
    }

    pub const fn num_non_leaf_nodes() -> u16 {
        NUM_LEAVES as u16 - 1
    }

    pub const fn depth() -> u16 {
        // Since NUM_LEAVES is always a power of 2
        NUM_LEAVES.trailing_zeros() as u16
    }

    #[inline(always)]
    fn left_child_index(node_index: u16) -> u16 {
        2 * node_index + 1
    }

    #[inline(always)]
    fn right_child_index(node_index: u16) -> u16 {
        2 * node_index + 2
    }

    #[inline(always)]
    fn parent_index(node_index: u16) -> u16 {
        (node_index - 1) / 2
    }

    #[inline(always)]
    fn sibling_index(node_index: u16) -> u16 {
        if node_index % 2 == 1 {
            node_index + 1
        } else {
            node_index - 1
        }
    }

    #[inline(always)]
    pub const fn zero_seed() -> Seed<SEED_SIZE> {
        [0; SEED_SIZE]
    }

    pub fn random_seed<R: RngCore>(rng: &mut R) -> Seed<SEED_SIZE> {
        let mut seed = [0u8; SEED_SIZE];
        rng.fill_bytes(&mut seed);
        seed
    }
}

pub fn get_num_total_nodes(num_leaves: u16) -> u16 {
    2 * num_leaves - 1
}

pub fn get_num_leaves(depth: u16) -> u16 {
    1 << depth
}

pub fn get_depth(num_leaves: u16) -> u16 {
    let n = num_leaves as f32;
    n.log2().ceil() as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    use sha3::Shake256;

    fn random_vec(len: usize) -> Vec<u8> {
        let mut rng = StdRng::from_entropy();
        let mut random_vector = vec![0u8; len];
        rng.fill_bytes(&mut random_vector);
        random_vector
    }

    #[test]
    fn seed_tree_create() {
        let mut rng = StdRng::from_entropy();
        const SEED_SIZE: usize = 16;

        macro_rules! run_test {
            ($num_leaves: expr) => {{
                let depth = get_depth($num_leaves as u16) as usize;
                let num_nodes = get_num_total_nodes($num_leaves as u16) as usize;

                let salt = random_vec(32);
                let rep_index = 5;

                let tree = SeedTree::<$num_leaves, SEED_SIZE>::create::<_, Shake256>(
                    &mut rng,
                    salt.as_slice(),
                    rep_index,
                );
                assert_eq!(tree.0.len(), num_nodes);
                assert_eq!(
                    SeedTree::<$num_leaves, SEED_SIZE>::num_total_nodes() as usize,
                    num_nodes
                );
                assert_eq!(SeedTree::<$num_leaves, SEED_SIZE>::depth() as usize, depth);
                assert_eq!(
                    SeedTree::<$num_leaves, SEED_SIZE>::num_non_leaf_nodes() as usize,
                    num_nodes - $num_leaves
                );
                for i in 0..$num_leaves {
                    let leaf_seed_i = tree.get_leaf(i as u16);
                    assert_ne!(leaf_seed_i, SeedTree::<$num_leaves, SEED_SIZE>::zero_seed());
                }
            }};
        }

        run_test!(128);
        run_test!(256);
    }

    #[test]
    fn seed_tree_openings() {
        let mut rng = StdRng::from_entropy();

        const SEED_SIZE: usize = 16;

        macro_rules! run_test {
            ($num_leaves: expr) => {{
                let depth = get_depth($num_leaves as u16) as usize;

                let salt = random_vec(32);
                let rep_index = 5;

                let tree = SeedTree::<$num_leaves, SEED_SIZE>::create::<_, Shake256>(
                    &mut rng,
                    salt.as_slice(),
                    rep_index,
                );

                for unopened_party in 0..$num_leaves - 1 {
                    let opening = tree.open_seeds(unopened_party as u16);
                    assert_eq!(opening.len(), depth);
                    let tree2 = SeedTree::<$num_leaves, SEED_SIZE>::reconstruct_tree::<Shake256>(
                        unopened_party as u16,
                        &opening,
                        &salt,
                        rep_index,
                    )
                    .unwrap();

                    for i in 0..$num_leaves {
                        if i != unopened_party {
                            assert_eq!(tree.get_leaf(i as u16), tree2.get_leaf(i as u16));
                        } else {
                            assert_eq!(
                                tree2.get_leaf(i as u16),
                                SeedTree::<$num_leaves, SEED_SIZE>::zero_seed()
                            );
                        }
                    }
                }
            }};
        }

        run_test!(128);
        run_test!(256);
    }
}
