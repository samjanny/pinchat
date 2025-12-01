use crate::state::AppState;
use std::time::Duration;

/// Starts the cleanup task for expired rooms with configurable interval
///
/// # Arguments
/// * `state` - Application state
/// * `interval_secs` - Cleanup interval in seconds (e.g., 60)
pub fn start_cleanup_task(state: AppState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;
            cleanup_expired_rooms(&state).await;
        }
    });
}

/// Removes all expired rooms
async fn cleanup_expired_rooms(state: &AppState) {
    let mut expired_rooms = Vec::new();

    // Identify expired rooms before mutating the collection to minimize lock contention
    for entry in state.rooms.iter() {
        let room_id = *entry.key();
        let room = entry.value();

        if room.is_expired() {
            expired_rooms.push(room_id);
        }
    }

    // Remove expired rooms once the full set has been gathered
    for room_id in expired_rooms {
        #[cfg(debug_assertions)]
        tracing::debug!("Cleaning up expired room");
        state.remove_room(&room_id);
    }

    // Emit cleanup statistics in debug builds to aid observability during development
    #[cfg(debug_assertions)]
    if state.total_rooms() > 0 {
        tracing::debug!(
            "Cleanup complete. Active rooms: {}, Active connections: {}",
            state.total_rooms(),
            state.total_connections()
        );
    }
}
