//! Scrollbar state management for the connections view.
//!
//! This module handles scrollbar rendering and state management.

use ratatui::{
    layout::Margin,
    widgets::{Scrollbar, ScrollbarOrientation},
    Frame,
};

/// Render the scrollbar for the connections table.
pub fn render_scrollbar(
    scroll_state: &mut ratatui::widgets::ScrollbarState,
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    num_items: usize,
) {
    *scroll_state = scroll_state.content_length(num_items);
    frame.render_stateful_widget(
        Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None),
        area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        }),
        scroll_state,
    );
}
