//! Table rendering logic for the connections view.
//!
//! This module contains the main table rendering functionality.

use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Style, Stylize},
    text::Text,
    widgets::{Cell, HighlightSpacing, Paragraph, Row, Table, TableState},
    Frame,
};
use std::{collections::HashMap, time::Duration};

use crate::tui_mod::ui::theme::Theme;
use netui::constants::{WIDTH_COMPACT, WIDTH_FULL_DETAIL, WIDTH_MIDDLE, WIDTH_NO_RTT};
use netui::stats::{AppRegistry, ConnectionDetails, IpPair, QualityMetrics, Speed, TcpState};

use super::formatter::{
    direction_arrow, format_age, format_local_endpoint, format_remote_endpoint, initiation_arrow,
};

type ConnectionData<'a> = &'a [(ConnectionDetails, TcpState, Speed, Option<Duration>)];

/// Render the connections table.
pub fn render_table(
    connections: ConnectionData,
    app_registry: &AppRegistry,
    quality_metrics: &HashMap<IpPair, QualityMetrics>,
    table_state: &mut TableState,
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
) {
    // Show empty state if no connections
    if connections.is_empty() {
        let empty =
            Paragraph::new("No active connections detected.\n\nPress 's' to scan for hosts.")
                .style(theme.base_text())
                .centered()
                .block(theme.bordered_block("Empty"));
        frame.render_widget(empty, area);
        return;
    }

    let header_style = theme.header_style();
    let selected_row_style = theme.selected_row_style();

    let header = [
        "State",
        "↑↓",
        "Local",
        "Dir",
        "Remote",
        "↓ Speed",
        "↑ Speed",
        "RTT",
        "Age",
    ]
    .into_iter()
    .map(Cell::from)
    .collect::<Row>()
    .style(header_style)
    .height(1);

    let rows = connections
        .iter()
        .enumerate()
        .map(|(i, (details, state, speed, age_opt))| {
            let row_bg = theme.row_background(i);

            let pair = details.as_ip_pair();
            let alert_prefix = alert_symbol(&pair, quality_metrics);
            let row_data = build_row_data(
                details,
                state,
                speed,
                age_opt,
                app_registry,
                quality_metrics,
                &pair,
                alert_prefix,
            );
            let row_style = row_style_for_connection(&pair, row_bg, quality_metrics, theme);

            // Build cells with individual styling for state column (index 0)
            let cells: Vec<Cell> = row_data
                .into_iter()
                .enumerate()
                .map(|(col_idx, content)| {
                    if col_idx == 0 {
                        // State column - apply color based on TCP state
                        Cell::from(Text::from(content))
                            .fg(state_color(state, theme))
                            .bg(row_bg)
                    } else {
                        // Other columns - use row style
                        Cell::from(Text::from(content))
                            .fg(row_style.fg.unwrap_or(theme.text_primary))
                            .bg(row_bg)
                    }
                })
                .collect();

            Row::new(cells).height(1)
        });

    // Responsive column widths based on terminal width
    let constraints = get_responsive_constraints(area.width);

    let bar = " ━ ";
    let table = Table::new(rows, constraints)
        .header(header)
        .row_highlight_style(selected_row_style)
        .highlight_symbol(Text::from(vec![bar.into()]))
        .bg(theme.background)
        .highlight_spacing(HighlightSpacing::Always);

    frame.render_stateful_widget(table, area, table_state);
}

/// Build the row data array for a connection.
fn build_row_data(
    details: &ConnectionDetails,
    state: &TcpState,
    speed: &Speed,
    age_opt: &Option<Duration>,
    app_registry: &AppRegistry,
    quality_metrics: &HashMap<IpPair, QualityMetrics>,
    pair: &IpPair,
    alert_prefix: &str,
) -> [String; 9] {
    let rtt_display = format_rtt_display(quality_metrics, pair);
    let app_name = app_registry
        .get_app_name(details.dst_port)
        .map(|s| s.as_str());
    let dir_arrow = direction_arrow(speed.input, speed.output);
    let init_arrow = initiation_arrow(details.direction);
    let age_display = age_opt.map(format_age).unwrap_or_default();

    let state_display = match state {
        TcpState::Closed => {
            // For non-TCP protocols, show protocol name instead of "CLS"
            if details.protocol == netui::constants::PROTOCOL_UDP {
                format!("[UDP]")
            } else if details.protocol == netui::constants::PROTOCOL_ICMP {
                format!("[ICMP]")
            } else {
                format!("[{}]", state.short_name_3char())
            }
        }
        _ => format!("[{}]", state.short_name_3char()),
    };

    // Prepend alert symbol to state column
    let state_with_alert = format!("{}{}", alert_prefix, state_display);

    [
        state_with_alert,
        dir_arrow.to_string(),
        format_local_endpoint(&details.src_ip.to_string(), details.src_port),
        init_arrow.to_string(),
        format_remote_endpoint(&details.dst_ip.to_string(), details.dst_port, app_name, 25),
        speed.to_string_input(),
        speed.to_string_output(),
        rtt_display,
        age_display,
    ]
}

/// Format the RTT display based on quality metrics.
fn format_rtt_display(quality_metrics: &HashMap<IpPair, QualityMetrics>, pair: &IpPair) -> String {
    quality_metrics
        .get(pair)
        .map(|q| {
            if q.score < 80 {
                format!("{:.0}ms", q.rtt_ms())
            } else {
                String::new()
            }
        })
        .unwrap_or_default()
}

/// Get the row style based on quality metrics.
fn row_style_for_connection(
    pair: &IpPair,
    row_bg: Color,
    quality_metrics: &HashMap<IpPair, QualityMetrics>,
    theme: &Theme,
) -> Style {
    let alert_style = quality_metrics.get(pair).map(|q| {
        if q.score < 40 {
            (true, theme.alert_critical, "⚠ ")
        } else if q.rtt_ms() > 100.0 || q.retransmit_rate() > 5.0 {
            (true, theme.alert_warning, "⚡ ")
        } else {
            (false, theme.text_primary, "")
        }
    });

    if let Some((is_alert, color, _symbol)) = alert_style {
        if is_alert {
            Style::new().fg(color).bg(row_bg)
        } else {
            Style::new().fg(theme.text_primary).bg(row_bg)
        }
    } else {
        Style::new().fg(theme.text_primary).bg(row_bg)
    }
}

/// Get alert symbol based on quality metrics.
fn alert_symbol(pair: &IpPair, quality_metrics: &HashMap<IpPair, QualityMetrics>) -> &'static str {
    if let Some(q) = quality_metrics.get(pair) {
        if q.score < 40 {
            "⚠ "
        } else if q.rtt_ms() > 100.0 || q.retransmit_rate() > 5.0 {
            "⚡ "
        } else {
            ""
        }
    } else {
        ""
    }
}

/// Get the color for a TCP state in the state column.
fn state_color(state: &TcpState, theme: &Theme) -> Color {
    match state {
        TcpState::Established => theme.tcp_established,
        TcpState::SynSent | TcpState::SynReceived => theme.tcp_syn,
        TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing => theme.tcp_fin,
        TcpState::TimeWait => theme.tcp_time_wait,
        TcpState::CloseWait | TcpState::LastAck => theme.tcp_close,
        TcpState::Closed => theme.tcp_closed,
        TcpState::Unknown => theme.tcp_unknown,
    }
}

/// Get responsive column constraints based on terminal width.
fn get_responsive_constraints(width: u16) -> [Constraint; 9] {
    if width >= WIDTH_FULL_DETAIL {
        // Full detail view - all columns shown
        [
            Constraint::Length(7),  // State: [EST] or ⚠ [EST]
            Constraint::Length(3),  // Direction: ↓↑↔
            Constraint::Length(21), // Local: 192.168.1.5:54321
            Constraint::Length(3),  // Initiation: →←
            Constraint::Min(28),    // Remote: IP:PORT (App) expanded
            Constraint::Min(13),    // ↓ Speed
            Constraint::Min(13),    // ↑ Speed
            Constraint::Length(8),  // RTT
            Constraint::Length(7),  // Age
        ]
    } else if width >= WIDTH_NO_RTT {
        // Show RTT
        [
            Constraint::Length(7),
            Constraint::Length(3),
            Constraint::Length(20),
            Constraint::Length(3),
            Constraint::Min(25),
            Constraint::Min(12),
            Constraint::Min(12),
            Constraint::Length(8), // RTT
            Constraint::Length(7),
        ]
    } else if width >= WIDTH_MIDDLE {
        // Middle ground - show RTT but shorter columns
        [
            Constraint::Length(7),
            Constraint::Length(3),
            Constraint::Length(18),
            Constraint::Length(3),
            Constraint::Min(22),
            Constraint::Min(11),
            Constraint::Min(11),
            Constraint::Length(8), // RTT
            Constraint::Length(7),
        ]
    } else if width >= WIDTH_COMPACT {
        // Hide RTT
        [
            Constraint::Length(7),
            Constraint::Length(3),
            Constraint::Length(18),
            Constraint::Length(3),
            Constraint::Min(22),
            Constraint::Min(10),
            Constraint::Min(10),
            Constraint::Length(0), // RTT hidden
            Constraint::Length(7),
        ]
    } else {
        // Minimal view
        [
            Constraint::Length(7),
            Constraint::Length(3),
            Constraint::Min(14),
            Constraint::Length(3),
            Constraint::Min(18),
            Constraint::Min(8),
            Constraint::Min(8),
            Constraint::Length(0),
            Constraint::Length(0),
        ]
    }
}
