//! Help modal component for displaying keybindings and instructions.
//!
//! This module provides a help overlay that shows all available
//! keybindings and their descriptions.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

/// Help modal content showing all available keybindings.
pub struct HelpModal {
    /// Whether the help modal is currently visible
    pub visible: bool,
}

impl HelpModal {
    /// Create a new help modal.
    pub fn new() -> Self {
        Self { visible: false }
    }

    /// Render the help modal overlay.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        if !self.visible {
            return;
        }

        // Create a centered modal area
        let popup_area = Self::centered_popup(area, 60, 70);

        // Build help content
        let help_content = self.build_help_content();

        let block = Block::default()
            .title(" Keybindings & Help ")
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let paragraph = Paragraph::new(help_content)
            .block(block)
            .wrap(Wrap { trim: false })
            .alignment(Alignment::Left);

        // Clear the background area first
        frame.render_widget(Clear, popup_area);
        frame.render_widget(paragraph, popup_area);
    }

    /// Calculate centered popup area.
    fn centered_popup(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ])
            .split(area);

        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ])
            .split(vertical[1])[1]
    }

    /// Build the help content with all keybindings.
    fn build_help_content(&self) -> Vec<Line<'static>> {
        vec![
            Line::from(vec![
                Span::styled(
                    "Navigation",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(":"),
            ]),
            Line::from("  j/k or ↑/↓     Move down/up"),
            Line::from("  l/h            Switch views (Hosts ↔ Connections ↔ Apps)"),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Actions",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(":"),
            ]),
            Line::from("  s             Send ARP requests (scan network)"),
            Line::from("  t             Toggle speed mode (Average/Instant/Peak)"),
            Line::from("  c (twice)      Clean selected host (and older)"),
            Line::from("                 Requires double-press to confirm"),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Application",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(":"),
            ]),
            Line::from("  q or ESC      Quit application"),
            Line::from("  Ctrl-C        Quit application"),
            Line::from("  ?             Toggle this help screen"),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "View Modes",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(":"),
            ]),
            Line::from("  Hosts         Display discovered network hosts"),
            Line::from("  Connections   Display active connections with bandwidth"),
            Line::from("  Apps          Display applications by bandwidth usage"),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Connection Symbols",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(":"),
            ]),
            Line::from("  →             Outgoing (you initiated)"),
            Line::from("  ←             Incoming (remote initiated)"),
            Line::from("  ↔             Local-to-local connection"),
            Line::from("  INET          Internet (through gateway)"),
            Line::from("  ?             Unknown direction"),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Press Esc, q, or ? to close",
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::ITALIC),
            )]),
        ]
    }
}

impl Default for HelpModal {
    fn default() -> Self {
        Self::new()
    }
}
