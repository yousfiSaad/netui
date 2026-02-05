use chrono::{Duration, Local};
use ratatui::{
    layout::{Constraint, Margin, Rect},
    style::{Modifier, Style, Stylize},
    text::Text,
    widgets::{
        Cell, HighlightSpacing, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState,
    },
    Frame,
};

use netui::host::Host;
use netui::mac_vendor;
use netui::stats::StatsAggregator;
use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::tui_mod::ui::components::sparkline::Sparkline;
use crate::tui_mod::ui::theme::Theme;
use netui::constants::{MAX_VENDOR_LENGTH, SPARKLINE_WIDTH};

pub struct HostsTable<'a> {
    items: &'a Vec<Host>,
    new_hosts: &'a HashSet<Ipv4Addr>,
    mac_changed_hosts: &'a HashSet<Ipv4Addr>,
    local_ips: &'a HashSet<Ipv4Addr>,
    stats_aggregator: &'a StatsAggregator,
    longest_item_lens: (u16, u16, u16, u16, u16, u16, u16), // (ip, status, mac, speed_down, speed_up, trend, time)
    theme: &'a Theme,
}

impl<'a> HostsTable<'a> {
    pub fn new(
        data_vec: &'a Vec<Host>,
        new_hosts: &'a HashSet<Ipv4Addr>,
        mac_changed_hosts: &'a HashSet<Ipv4Addr>,
        local_ips: &'a HashSet<Ipv4Addr>,
        stats_aggregator: &'a StatsAggregator,
        theme: &'a Theme,
    ) -> Self {
        Self {
            longest_item_lens: Self::constraint_len_calculator(data_vec, stats_aggregator),
            items: data_vec,
            new_hosts,
            mac_changed_hosts,
            local_ips,
            stats_aggregator,
            theme,
        }
    }

    pub fn render_table(&mut self, table_state: &mut TableState, frame: &mut Frame, area: Rect) {
        // Show empty state if no hosts
        if self.items.is_empty() {
            let empty = Paragraph::new(
                "No hosts discovered yet.\n\nPress 's' to send ARP discovery packets.",
            )
            .style(self.theme.base_text())
            .centered()
            .block(self.theme.bordered_block("Empty"));
            frame.render_widget(empty, area);
            return;
        }

        let header_style = self.theme.header_style();
        let selected_row_style = self.theme.selected_row_style();
        let selected_col_style = Style::default().fg(self.theme.selection_fg);
        let selected_cell_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.theme.selection_fg);

        let header = [
            "IP Address",
            "Status",
            "Mac Address",
            "Speed ↓",
            "Speed ↑",
            "Trend",
            "Time",
        ]
        .into_iter()
        .map(Cell::from)
        .collect::<Row>()
        .style(header_style)
        .height(1);

        // Cache current time once per render instead of calling for each row
        let now = Local::now();

        let constraints = Self::get_responsive_constraints(area.width, self.longest_item_lens);

        let rows = self.items.iter().enumerate().map(|(i, host)| {
            let row_bg = self.theme.row_background(i);

            let row = [
                self.render_ip_column(host),
                self.render_status_column(host),
                self.render_mac_column(host),
                self.render_speed_down_column(host),
                self.render_speed_up_column(host),
                self.render_trend_column(host),
                self.render_time_column(host, now),
            ];

            let row_style = self.row_style(host, row_bg);

            row.into_iter()
                .map(|content| Cell::from(Text::from(content)))
                .collect::<Row>()
                .style(row_style)
                .height(1)
        });

        let bar = " ━ ";
        let table = Table::new(rows, constraints)
            .header(header)
            .row_highlight_style(selected_row_style)
            .column_highlight_style(selected_col_style)
            .cell_highlight_style(selected_cell_style)
            .highlight_symbol(Text::from(vec![bar.into()]))
            .bg(self.theme.background)
            .highlight_spacing(HighlightSpacing::Always);
        frame.render_stateful_widget(table, area, table_state);
    }

    pub fn render_scrollbar(
        &mut self,
        scroll_state: &mut ScrollbarState,
        frame: &mut Frame,
        area: Rect,
    ) {
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

    fn constraint_len_calculator(
        items: &[Host],
        _stats_aggregator: &StatsAggregator,
    ) -> (u16, u16, u16, u16, u16, u16, u16) {
        let ip_len = items
            .iter()
            .map(|h| h.ipv4.to_string().len())
            .max()
            .unwrap_or(0);
        let status_len = 1; // Status column shows single icon (● or ⟳) or empty
        let mac_len = items
            .iter()
            .map(|h| h.mac.to_string().len())
            .max()
            .unwrap_or(0);
        let speed_down_len = items
            .iter()
            .map(|h| h.speed.map(|s| s.to_string_input().len()).unwrap_or(0))
            .max()
            .unwrap_or(0);
        let speed_up_len = items
            .iter()
            .map(|h| h.speed.map(|s| s.to_string_output().len()).unwrap_or(0))
            .max()
            .unwrap_or(0);
        let trend_len = SPARKLINE_WIDTH;
        let time_len = items
            .iter()
            .map(|h| h.time.to_string().len())
            .max()
            .unwrap_or(0);

        #[allow(clippy::cast_possible_truncation)]
        (
            ip_len as u16,
            status_len,
            mac_len as u16,
            speed_down_len as u16,
            speed_up_len as u16,
            trend_len as u16,
            time_len as u16,
        )
    }

    /// Get responsive column constraints based on terminal width.
    fn get_responsive_constraints(
        width: u16,
        longest_item_lens: (u16, u16, u16, u16, u16, u16, u16),
    ) -> [Constraint; 7] {
        if width >= 110 {
            // Full detail view
            [
                Constraint::Length(longest_item_lens.0 + 2), // IP
                Constraint::Length(7),                       // Status column width
                Constraint::Min(longest_item_lens.2 + 12),   // MAC with vendor
                Constraint::Min(13),                         // Speed down
                Constraint::Min(13),                         // Speed up
                Constraint::Length(SPARKLINE_WIDTH as u16),  // Trend
                Constraint::Min(12),                         // Time
            ]
        } else if width >= 90 {
            // Hide trend, shorter columns
            [
                Constraint::Min(16),    // IP
                Constraint::Length(7),  // Status
                Constraint::Min(15),    // MAC
                Constraint::Min(10),    // Speed down
                Constraint::Min(10),    // Speed up
                Constraint::Length(0),  // Trend hidden
                Constraint::Length(10), // Time
            ]
        } else {
            // Minimal view
            [
                Constraint::Min(13),   // IP
                Constraint::Length(7), // Status
                Constraint::Min(12),   // MAC
                Constraint::Min(8),    // Speed down
                Constraint::Min(8),    // Speed up
                Constraint::Length(0), // Trend hidden
                Constraint::Length(8), // Time
            ]
        }
    }

    /// Render the IP column.
    fn render_ip_column(&self, host: &Host) -> String {
        host.ipv4.to_string()
    }

    /// Render the Status column with icons for new/changed hosts.
    fn render_status_column(&self, host: &Host) -> String {
        if self.mac_changed_hosts.contains(&host.ipv4) {
            "⟳".to_string() // MAC changed
        } else if self.new_hosts.contains(&host.ipv4) {
            "●".to_string() // New host
        } else {
            "".to_string()
        }
    }

    /// Render the MAC address column with vendor lookup.
    fn render_mac_column(&self, host: &Host) -> String {
        let mac_str = host.mac.to_string();
        if let Some(vendor) = mac_vendor::lookup_vendor(&host.mac) {
            let vendor_display = if vendor.len() > MAX_VENDOR_LENGTH {
                format!("{}..", &vendor[..MAX_VENDOR_LENGTH - 2])
            } else {
                vendor.to_string()
            };
            format!("{} ({})", mac_str, vendor_display)
        } else {
            mac_str
        }
    }

    /// Render the download speed column.
    fn render_speed_down_column(&self, host: &Host) -> String {
        if let Some(speed) = host.speed {
            speed.to_string_input()
        } else {
            String::from("")
        }
    }

    /// Render the upload speed column.
    fn render_speed_up_column(&self, host: &Host) -> String {
        if let Some(speed) = host.speed {
            speed.to_string_output()
        } else {
            String::from("")
        }
    }

    /// Render the trend column with sparkline visualization.
    fn render_trend_column(&self, host: &Host) -> String {
        let history = self.stats_aggregator.speed_history(Some(host.ipv4));
        let sparkline = Sparkline::from_speeds(&history, SPARKLINE_WIDTH);
        sparkline.render()
    }

    /// Render the time column showing how long ago the host was seen.
    fn render_time_column(&self, host: &Host, now: chrono::DateTime<Local>) -> String {
        let diff = now
            .signed_duration_since(host.time)
            .num_milliseconds()
            .max(0);
        let durr = Duration::milliseconds(diff);
        format!(
            "{:2} min {:2} sec ago",
            durr.num_minutes(),
            durr.num_seconds() - (durr.num_minutes() * 60)
        )
    }

    /// Get the style for a row based on host state.
    fn row_style(&self, host: &Host, row_bg: ratatui::style::Color) -> ratatui::style::Style {
        // Check if host is the local device
        let is_local_device = self.local_ips.contains(&host.ipv4);

        if self.mac_changed_hosts.contains(&host.ipv4) {
            Style::new()
                .fg(self.theme.mac_changed_warning)
                .bold()
                .bg(row_bg)
        } else if is_local_device {
            // Highlight local device with distinct color/style
            Style::new().fg(self.theme.header_fg).bold().bg(row_bg)
        } else {
            Style::new().fg(self.theme.text_primary).bg(row_bg)
        }
    }
}
