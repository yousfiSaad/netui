//! View and table navigation logic.
//!
//! This module contains all methods for navigating between views and
//! selecting rows in tables.

use crate::tui_mod::app::{events::ViewMode, state::App};

impl App {
    pub(crate) fn next_row(&mut self) {
        let item_count = self.current_item_count();
        let row_height = self.current_row_height();

        let i = match self.table_state.selected() {
            Some(i) => {
                if i + 1 >= item_count {
                    None
                } else {
                    Some(i + 1)
                }
            }
            None => Some(0),
        };
        self.table_state.select(i);
        self.scroll_state = self
            .scroll_state
            .position(i.unwrap_or(item_count.saturating_sub(1)) * row_height);
    }

    pub(crate) fn previous_row(&mut self) {
        let item_count = self.current_item_count();
        let row_height = self.current_row_height();

        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    None
                } else {
                    Some(i - 1)
                }
            }
            None => Some(item_count.saturating_sub(1)),
        };
        self.table_state.select(i);
        self.scroll_state = self.scroll_state.position(i.unwrap_or(0) * row_height);
    }

    /// Get the number of items in the current view
    pub(crate) fn current_item_count(&self) -> usize {
        match self.view_mode {
            ViewMode::Hosts => self.hosts.len(),
            ViewMode::Connections => self.stats_aggregator.connections_with_details().len(),
            ViewMode::Apps => self.stats_aggregator.apps_stats().len(),
        }
    }

    /// Get the row height for the current view
    pub(crate) fn current_row_height(&self) -> usize {
        match self.view_mode {
            ViewMode::Hosts => 4,                        // Hosts have multi-row layout
            ViewMode::Connections | ViewMode::Apps => 1, // Single-row tables
        }
    }
}
