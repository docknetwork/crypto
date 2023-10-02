/// Number of bits in `base`
pub fn base_bits(base: u16) -> u16 {
    base.ilog2() as u16
}
