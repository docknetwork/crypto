use std::{
    fmt::Debug,
    iter::Sum,
    ops::{Add, Div},
};

/// Prints the total, least, median, and the highest value of the given list
pub fn statistics<T, U>(mut values: Vec<T>) -> String
where
    T: Copy + Ord + Add<Output = T> + Sum<T> + Div<U, Output = T> + Debug,
    U: From<u8>,
{
    values.sort();
    let two = U::from(2);

    let median = {
        let mid = values.len() / 2;
        if values.len() % 2 == 0 {
            (values[mid - 1] + values[mid]) / two
        } else {
            values[mid]
        }
    };
    let total: T = values.iter().copied().sum();
    format!(
        "{:.2?} | [{:.2?}, {:.2?}, {:.2?}]",
        total,
        values.first().unwrap(),
        median,
        values.last().unwrap()
    )
}
