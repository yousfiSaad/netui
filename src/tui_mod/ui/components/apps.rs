//! Applications tab component.
//!
//! Displays bandwidth statistics grouped by application (HTTP, SSH, etc.).

use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style, Stylize},
    text::Text,
    widgets::{
        Block, BorderType, Cell, HighlightSpacing, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState,
    },
    Frame,
};

use crate::tui_mod::ui::theme::Theme;
use netui::stats::speed::format_size;

/// Applications table component showing bandwidth by application type.
pub struct Apps<'a> {
    theme: &'a Theme,
}

impl<'a> Apps<'a> {
    /// Create a new Apps component.
    pub fn new(theme: &'a Theme) -> Self {
        Self { theme }
    }

    /// Render the applications table.
    pub fn render(
        self,
        frame: &mut Frame,
        area: Rect,
        table_state: &mut TableState,
        apps_stats: Vec<netui::stats::AppStats>,
    ) {
        let header_style = Style::default()
            .fg(self.theme.header_fg)
            .bg(self.theme.header_bg);
        let selected_row_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.theme.selection_fg);

        let header = ["Application", "Download", "Upload", "Total", "%"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);

        let rows = apps_stats.iter().enumerate().map(|(i, app)| {
            let row_bg = if i % 2 == 0 {
                self.theme.background
            } else {
                self.theme.header_bg
            };

            let row = [
                app.name.clone(),
                app.speed.to_string_input(),
                app.speed.to_string_output(),
                format_size(app.speed.input + app.speed.output),
                format!("{:.1}%", app.percentage),
            ];

            row.into_iter()
                .map(|content| Cell::from(Text::from(content)))
                .collect::<Row>()
                .style(Style::new().fg(self.theme.text_primary).bg(row_bg))
                .height(1)
        });

        let bar = " ━ ";
        let table = Table::new(
            rows,
            [
                Constraint::Min(20),   // Application name
                Constraint::Min(15),   // Download
                Constraint::Min(15),   // Upload
                Constraint::Min(15),   // Total
                Constraint::Length(8), // Percentage
            ],
        )
        .header(header)
        .row_highlight_style(selected_row_style)
        .highlight_symbol(Text::from(vec![bar.into()]))
        .bg(self.theme.background)
        .highlight_spacing(HighlightSpacing::Always);

        let table_area = area;

        frame.render_stateful_widget(table, table_area, table_state);

        // Add scrollbar if needed
        if apps_stats.len() > 10 {
            frame.render_stateful_widget(
                Scrollbar::default()
                    .orientation(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None),
                table_area.inner(ratatui::layout::Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
                &mut ScrollbarState::new(apps_stats.len()).position(table_state.offset()),
            );
        }

        // Render info message if no apps
        if apps_stats.is_empty() {
            let info = Paragraph::new("No application data available yet.")
                .style(
                    Style::new()
                        .fg(self.theme.text_primary)
                        .bg(self.theme.background),
                )
                .centered()
                .block(
                    Block::bordered()
                        .border_type(BorderType::Double)
                        .border_style(Style::new().fg(self.theme.border_active)),
                );
            frame.render_widget(info, table_area);
        }
    }
}
