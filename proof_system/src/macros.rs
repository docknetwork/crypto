/// Expands provided expression.
#[macro_export]
macro_rules! expand_expr {
    ($statement: ident . $($tt: tt)+) => {
        $statement. $($tt)+
    };
    ($statement: ident: $($tt: tt)+) => {
        ($($tt)+)($statement)
    };
    ($statement: ident ($($tt: tt)+)) => {
        ($statement)($($tt)+)
    };
    ($statement: ident with variant as $ident: ident $($tt: tt)+) => {{
        let $ident = $statement;

        $($tt)+
    }}
}

/// Delegates provided expression to an indexed variant of the enum based.
#[macro_export]
macro_rules! delegate_indexed {
    ($self: ident $([$idx_var: ident $idx_val: expr])? => $($variants: ident),+: $($tt: tt)+) => {
        match &$self {
            $(Self::$variants(_) => {}),+
        }
        $crate::delegate_indexed!(@ $self $([$idx_var $idx_val])? => $($variants),+: $($tt)+)
    };
    (@ $self: ident $([$idx_var: ident $idx_val: expr])? => $variant: ident: $($tt: tt)+) => {
        if let Self::$variant(__variant) = $self {
            $(let $idx_var = $idx_val;)?
            return $crate::expand_expr!(__variant $($tt)+)
        }
        unreachable!()
    };
    (@ $self: ident $([$idx_var: ident $idx_val: expr])? => $variant: ident, $($next_variant: ident),+: $($tt: tt)+) => {
        if let Self::$variant(__variant) = $self {
            $(let $idx_var = $idx_val;)?
            return $crate::expand_expr!(__variant $($tt)+)
        }
        $crate::delegate_indexed!(@ $self $([$idx_var $idx_val + 1])? => $($next_variant),+: $($tt)+);
    };
}

/// Calls provided expression with a enum variant constructor based on an index.
#[macro_export]
macro_rules! delegate_indexed_reverse {
    ($val: ident [$idx_var: ident $idx_val: expr] => $variant: ident: $($tt: tt)+) => {
        if $idx_val == $val {
            let $idx_var = $val;
            let __variant = Self::$variant;
            return $crate::expand_expr!(__variant $($tt)+)
        }
    };
    ($val: ident [$idx_var: ident $idx_val: expr] => $variant: ident, $($next_variant: ident),+: $($tt: tt)+) => {
        if $idx_val == $val {
            let $idx_var = $val;
            let __variant = Self::$variant;
            return $crate::expand_expr!(__variant $($tt)+)
        }
        $crate::delegate_indexed_reverse!($val[$idx_var $idx_val + 1] => $($next_variant),+: $($tt)+);
    };
}
