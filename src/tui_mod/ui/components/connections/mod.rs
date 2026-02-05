//! Connections table widget.
//!
//! This module displays network connections with their states, speeds,
//! and quality metrics in a responsive table format.

mod formatter;
mod scrollbar;
mod table;

use ratatui::widgets::ScrollbarState;
use ratatui::Frame;

use std::{collections::HashMap, time::Duration};

use netui::stats::Speed;
use netui::stats::{AppRegistry, ConnectionDetails, IpPair, QualityMetrics, TcpState};

use crate::tui_mod::ui::theme::Theme;

type ConnectionData<'a> = &'a [(ConnectionDetails, TcpState, Speed, Option<Duration>)];

/// Connections table widget.
pub struct Connections<'a> {
    theme: &'a Theme,
}

impl<'a> Connections<'a> {
    pub fn new(theme: &'a Theme) -> Self {
        Self { theme }
    }

    pub fn render_table(
        &mut self,
        connections: ConnectionData,
        app_registry: &AppRegistry,
        quality_metrics: &HashMap<IpPair, QualityMetrics>,
        table_state: &mut ratatui::widgets::TableState,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
    ) {
        table::render_table(
            connections,
            app_registry,
            quality_metrics,
            table_state,
            frame,
            area,
            self.theme,
        );
    }

    pub fn render_scrollbar(
        &mut self,
        scroll_state: &mut ScrollbarState,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        num_items: usize,
    ) {
        scrollbar::render_scrollbar(scroll_state, frame, area, num_items);
    }
}
