//! Stats aggregator task spawning.
//!
//! This module handles spawning the background task that periodically
//! emits stat events by aggregating statistics from packet processing.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::event::{Event, ScannerEvent};
use crate::stats::StatsMap;
use crate::utils::recover_or_log;

/// Spawn the stats aggregator background task.
///
/// This function spawns a task that:
/// 1. Ticks every second
/// 2. Aggregates statistics from the shared stats map
/// 3. Emits StatTick events to the main event loop
/// 4. Resets the stats map after each tick
///
/// # Arguments
/// * `agg` - Shared statistics map wrapped in Arc<Mutex<>>
/// * `scanner_outputs` - Channel for sending scanner events
/// * `cancel_token` - Cancellation token for stopping the task
///
/// # Returns
/// A handle to the spawned task
pub fn spawn_stats_aggregator(
    agg: std::sync::Arc<std::sync::Mutex<StatsMap>>,
    scanner_outputs: mpsc::Sender<Event>,
    cancel_token: CancellationToken,
) -> JoinHandle<()> {
    let stats_cancel_token = cancel_token.child_token();
    let agg_clone = agg.clone();
    let scanner_outputs_clone = scanner_outputs.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = stats_cancel_token.cancelled() => {
                    tracing::debug!("Stats aggregator task cancelled, shutting down");
                    break;
                }
                _ = interval.tick() => {
                    let data_clone;
                    {
                        let mut data = recover_or_log(agg_clone.lock(), "stats aggregator");
                        data_clone = std::mem::take(&mut *data);
                    }
                    if let Err(e) = scanner_outputs_clone.send(Event::Scanner(ScannerEvent::StatTick(data_clone))).await {
                        tracing::error!("Failed to send StatTick event: {}", e);
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    // Note: This test is disabled because it requires a tokio runtime
    // In production, the scanner provides the runtime context
    #[tokio::test]
    async fn test_spawn_stats_aggregator_creates_handle() {
        let stats_map: StatsMap = HashMap::new();
        let aggregator = Arc::new(std::sync::Mutex::new(stats_map));
        let (tx, _rx) = mpsc::channel(10);
        let cancel_token = CancellationToken::new();

        let handle = spawn_stats_aggregator(aggregator, tx, cancel_token);
        // Just verify it creates a handle without panicking
        drop(handle);
    }
}
