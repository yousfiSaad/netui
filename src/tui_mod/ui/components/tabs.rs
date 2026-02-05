use ratatui::{
    layout::Rect,
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Tabs as RatatuiTabs},
    Frame,
};

use crate::tui_mod::app::ViewMode;
use crate::tui_mod::ui::theme::Theme;

pub struct Tabs<'a> {
    current_mode: ViewMode,
    theme: &'a Theme,
}

impl<'a> Tabs<'a> {
    pub fn new(current_mode: ViewMode, theme: &'a Theme) -> Self {
        Self {
            current_mode,
            theme,
        }
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let titles = vec![
            self.make_tab_title("Devices", ViewMode::Hosts),
            self.make_tab_title("Connections (Active)", ViewMode::Connections),
            self.make_tab_title("Apps (By Bandwidth)", ViewMode::Apps),
        ];

        let selected_index = match self.current_mode {
            ViewMode::Hosts => 0,
            ViewMode::Connections => 1,
            ViewMode::Apps => 2,
        };

        let tabs = RatatuiTabs::new(titles)
            .block(Block::default().style(self.theme.app_block()))
            .highlight_style(
                Style::default()
                    .fg(self.theme.tab_active_fg)
                    .bg(self.theme.tab_active_bg)
                    .bold(),
            )
            .select(selected_index)
            .padding("", "")
            .divider(" | ");

        frame.render_widget(tabs, area);
    }

    fn make_tab_title(&self, title: &str, mode: ViewMode) -> Line<'static> {
        let style = if self.current_mode == mode {
            Style::default().fg(self.theme.tab_active_fg)
        } else {
            Style::default().fg(self.theme.tab_inactive_fg)
        };
        Line::from(vec![Span::styled(title.to_string(), style)])
    }
}
