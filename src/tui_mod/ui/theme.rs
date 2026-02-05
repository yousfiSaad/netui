use ratatui::style::palette::tailwind;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Block;

pub struct Theme {
    pub background: Color,
    pub text_primary: Color,
    pub border_active: Color,
    pub selection_fg: Color,
    pub header_bg: Color,
    pub header_fg: Color,
    pub tab_active_fg: Color,
    pub tab_active_bg: Color,
    pub tab_inactive_fg: Color,
    pub mac_changed_warning: Color,
    pub alert_critical: Color,
    pub alert_warning: Color,
    pub tcp_established: Color,
    pub tcp_syn: Color,
    pub tcp_fin: Color,
    pub tcp_time_wait: Color,
    pub tcp_close: Color,
    pub tcp_closed: Color,
    pub tcp_unknown: Color,
    // Footer status colors
    pub status_active: Color,
    pub status_scanning: Color,
    pub status_idle: Color,
    pub footer_separator: Color,
    pub footer_dimmed: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            background: tailwind::SLATE.c950,
            text_primary: tailwind::SLATE.c200,
            border_active: tailwind::BLUE.c400,
            selection_fg: tailwind::BLUE.c300,
            header_bg: tailwind::SLATE.c900,
            header_fg: tailwind::SLATE.c200,
            tab_active_fg: tailwind::BLUE.c400,
            tab_active_bg: tailwind::SLATE.c900,
            tab_inactive_fg: tailwind::SLATE.c500,
            mac_changed_warning: tailwind::RED.c400,
            alert_critical: tailwind::RED.c400,
            alert_warning: tailwind::YELLOW.c400,
            tcp_established: tailwind::GREEN.c400,
            tcp_syn: tailwind::CYAN.c400,
            tcp_fin: tailwind::YELLOW.c400,
            tcp_time_wait: tailwind::BLUE.c400,
            tcp_close: tailwind::FUCHSIA.c400,
            tcp_closed: tailwind::SLATE.c600,
            tcp_unknown: tailwind::SLATE.c500,
            // Footer status colors
            status_active: tailwind::GREEN.c400,
            status_scanning: tailwind::YELLOW.c400,
            status_idle: tailwind::SLATE.c500,
            footer_separator: tailwind::SLATE.c700,
            footer_dimmed: tailwind::SLATE.c500,
        }
    }
}

impl Theme {
    pub fn app_block(&self) -> Style {
        Style::default().bg(self.background)
    }

    pub fn base_text(&self) -> Style {
        Style::default().fg(self.text_primary).bg(self.background)
    }

    pub fn header_style(&self) -> Style {
        Style::default().fg(self.header_fg).bg(self.header_bg)
    }

    pub fn selected_row_style(&self) -> Style {
        Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.selection_fg)
    }

    pub fn row_background(&self, row_index: usize) -> Color {
        if row_index % 2 == 0 {
            self.background
        } else {
            self.header_bg
        }
    }

    pub fn bordered_block<'a>(&self, title: &'a str) -> Block<'a> {
        Block::bordered()
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::new().fg(self.border_active))
            .title(title)
    }
}
