//! Mutex utilities for safe poison recovery.
//!
//! This module provides helper functions for handling poisoned mutexes
//! in a graceful manner by logging the error and recovering the inner value.

use std::sync::MutexGuard;

/// Unwrap a mutex lock result, recovering from poison by logging and extracting the inner value.
///
/// This function provides a consistent way to handle poisoned mutexes throughout the codebase.
/// When a mutex is poisoned (due to a panic while holding the lock), this function logs the
/// error and returns the inner value, allowing the application to continue running.
///
/// # Arguments
/// * `lock_result` - The result of a mutex lock operation
/// * `context` - A description of where the lock was acquired, for logging purposes
///
/// # Returns
/// A mutex guard containing the locked data
///
/// # Example
/// ```rust
/// # #[cfg(feature = "test-utils")]
/// # {
/// use crate::utils::mutex::recover_or_log;
///
/// let mutex = std::sync::Mutex::new(42);
/// let guard = recover_or_log(mutex.lock(), "example context");
/// # }
/// ```
pub fn recover_or_log<'a, T>(
    lock_result: Result<MutexGuard<'a, T>, std::sync::PoisonError<MutexGuard<'a, T>>>,
    context: &str,
) -> MutexGuard<'a, T> {
    match lock_result {
        Ok(guard) => guard,
        Err(e) => {
            tracing::error!("Mutex poisoned in {}, recovering: {}", context, e);
            e.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    #[test]
    fn test_recover_or_log_success() {
        let mutex = Mutex::new(42);
        let result = recover_or_log(mutex.lock(), "test context");
        assert_eq!(*result, 42);
    }

    #[test]
    fn test_recover_or_log_poisoned() {
        let mutex = Arc::new(Mutex::new(42));
        let mutex_clone = Arc::clone(&mutex);

        // Poison the mutex
        let _ = thread::spawn(move || {
            let _lock = mutex_clone.lock().unwrap();
            panic!("Intentional panic to poison mutex");
        })
        .join();

        // Recover from poison
        let result = recover_or_log(mutex.lock(), "test context");
        assert_eq!(*result, 42);
    }
}
