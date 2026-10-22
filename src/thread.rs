//! Fallible thread creation shared by all worker pools.
use std::thread::{Builder, Scope, ScopedJoinHandle};

pub(crate) fn spawn<'scope, 'env, F, T>(
    scope: &'scope Scope<'scope, 'env>,
    f: F,
) -> std::io::Result<ScopedJoinHandle<'scope, T>>
where
    F: FnOnce() -> T + Send + 'scope,
    T: Send + 'scope,
{
    #[cfg(test)]
    FAIL_AFTER.with(|remaining| {
        if let Some(n) = remaining.get() {
            if n == 0 {
                return Err(std::io::Error::other("injected thread spawn failure"));
            }
            remaining.set(Some(n - 1));
        }
        Ok(())
    })?;
    Builder::new().spawn_scoped(scope, f)
}

#[cfg(test)]
thread_local! {
    static FAIL_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn fail_after<T>(n: usize, f: impl FnOnce() -> T) -> T {
    struct Reset(Option<usize>);
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_AFTER.with(|v| v.set(self.0));
        }
    }
    let _reset = Reset(FAIL_AFTER.with(|v| v.replace(Some(n))));
    f()
}
