#[macro_export]
macro_rules! iterator {
    ($iterable:expr) => {
        {
            #[cfg(not(target_arch = "wasm32"))]
            {
                use rayon::prelude::*;
                $iterable.par_iter()
            }

            #[cfg(target_arch = "wasm32")]
            {
                $iterable.iter()
            }
        }
    };
}

#[macro_export]
macro_rules! windows {
    ($iterable:expr, $window_len:expr) => {
        {
            #[cfg(not(target_arch = "wasm32"))]
            let iterator = $iterable.par_windows($window_len);

            #[cfg(target_arch = "wasm32")]
            let iterator = $iterable.windows($window_len);

            iterator
        }
    };
}
