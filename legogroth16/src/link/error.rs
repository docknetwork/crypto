#[derive(Clone, Debug, PartialEq)]
pub enum LinkError {
    InvalidIndex(usize, usize),
    VectorLongerThanExpected(usize, usize),
    VectorWithUnexpectedLength(usize, usize),
    InvalidProof,
}
