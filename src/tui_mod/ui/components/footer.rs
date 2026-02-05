use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::tui_mod::app::App;
use crate::tui_mod::ui::components::sparkline::Sparkline;
use crate::tui_mod::ui::theme::Theme;

pub struct Footer<'a> {
    app: &'a App,
    theme: &'a Theme,
}

impl<'a> Footer<'a> {
    pub fn new(app: &'a App, theme: &'a Theme) -> Self {
        Self { app, theme }
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        // Compact single-line layout - all left-aligned to maximize space efficiency
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(11), // Status: "● Scanning"
                Constraint::Length(9),  // Hosts: "12 hosts"
                Constraint::Length(16), // Interface (truncated)
                Constraint::Min(25),    // Speed + sparkline (takes remaining)
            ])
            .split(area);

        // Render each section with left alignment for tight packing
        self.render_status(frame, layout[0]);
        self.render_hosts(frame, layout[1]);
        self.render_interface(frame, layout[2]);
        self.render_speed_and_sparkline(frame, layout[3]);
    }

    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let (dot_color, status_text) = if self.app.sending_arps {
            (self.theme.status_scanning, "Scanning")
        } else if !self.app.hosts.is_empty() {
            (self.theme.status_active, "Active")
        } else {
            (self.theme.status_idle, "Idle")
        };

        let line = Line::from(vec![
            Span::styled("●", Style::default().fg(dot_color)),
            Span::styled(format!(" {} ", status_text), self.theme.base_text()),
        ]);

        frame.render_widget(Paragraph::new(line).alignment(Alignment::Left), area);
    }

    fn render_hosts(&self, frame: &mut Frame, area: Rect) {
        let hosts_text = format!("{} hosts", self.app.hosts.len());
        let line = Line::from(vec![
            Span::styled(hosts_text, self.theme.base_text()),
            Span::styled(" │ ", Style::default().fg(self.theme.footer_separator)),
        ]);

        frame.render_widget(Paragraph::new(line).alignment(Alignment::Left), area);
    }

    fn render_interface(&self, frame: &mut Frame, area: Rect) {
        let interface_text = if self.app.interface.len() > 12 {
            format!("{}...", &self.app.interface[..9])
        } else {
            self.app.interface.clone()
        };

        let line = Line::from(vec![
            Span::styled(interface_text, self.theme.base_text()),
            Span::styled(" │ ", Style::default().fg(self.theme.footer_separator)),
        ]);

        frame.render_widget(Paragraph::new(line).alignment(Alignment::Left), area);
    }

    fn render_speed_and_sparkline(&self, frame: &mut Frame, area: Rect) {
        // Get speed value based on mode
        let speed_val = match self.app.speed_mode {
            crate::tui_mod::app::SpeedDisplayMode::Average => self.app.stats_aggregator.speed_str(),
            crate::tui_mod::app::SpeedDisplayMode::Instant => {
                self.app.stats_aggregator.total_speed_instant().to_string()
            }
            crate::tui_mod::app::SpeedDisplayMode::Peak => {
                self.app.stats_aggregator.total_speed_peak().to_string()
            }
        };

        // Get sparkline - dynamic width based on available space
        let speed_history = self.app.stats_aggregator.speed_history(None);
        // Reserve space for mode indicator, arrow, speed value, and spacing (~15 chars)
        let sparkline_width = (area.width as usize).saturating_sub(15).max(10);
        let sparkline = Sparkline::from_speeds(&speed_history, sparkline_width);
        let sparkline_text = sparkline.render();

        // Build the speed line with mode indicator
        let mode_char = match self.app.speed_mode {
            crate::tui_mod::app::SpeedDisplayMode::Average => "A",
            crate::tui_mod::app::SpeedDisplayMode::Instant => "I",
            crate::tui_mod::app::SpeedDisplayMode::Peak => "P",
        };

        let line = Line::from(vec![
            Span::styled(
                format!("[{}] ", mode_char),
                Style::default().fg(self.theme.footer_dimmed),
            ),
            Span::styled("▼", Style::default().fg(self.theme.tcp_syn)),
            Span::styled(format!(" {} ", speed_val), self.theme.base_text()),
            Span::styled(
                sparkline_text,
                Style::default().fg(self.theme.border_active),
            ),
        ]);

        frame.render_widget(Paragraph::new(line).alignment(Alignment::Left), area);
    }
}
