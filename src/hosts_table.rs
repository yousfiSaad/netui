//! # [Ratatui] Table example
//!
//! The latest version of this example is available in the [examples] folder in the repository.
//!
//! Please note that the examples are designed to be run against the `main` branch of the Github
//! repository. This means that you may not be able to compile with the latest release version on
//! crates.io, or the one that you have installed locally.
//!
//! See the [examples readme] for more information on finding examples that match the version of the
//! library you are using.
//!
//! [Ratatui]: https://github.com/ratatui/ratatui
//! [examples]: https://github.com/ratatui/ratatui/blob/main/examples
//! [examples readme]: https://github.com/ratatui/ratatui/blob/main/examples/README.md

use chrono::{Duration, Local};
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::{self, Color, Modifier, Style, Stylize},
    text::Text,
    widgets::{
        Block, BorderType, Cell, HighlightSpacing, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState,
    },
    Frame,
};
use style::palette::tailwind;

use crate::app::Host;

const PALETTES: [tailwind::Palette; 4] = [
    tailwind::BLUE,
    tailwind::EMERALD,
    tailwind::INDIGO,
    tailwind::RED,
];
const INFO_TEXT: [&str; 2] = [
    "(q) quit | (k) move up | (j) move down | (h) move left | (l) move right",
    "(s) send ARP requests | (c) clean current and older hosts",
];

struct TableColors {
    buffer_bg: Color,
    header_bg: Color,
    header_fg: Color,
    row_fg: Color,
    selected_row_style_fg: Color,
    selected_column_style_fg: Color,
    selected_cell_style_fg: Color,
    normal_row_color: Color,
    alt_row_color: Color,
    help_border_color: Color,
}

impl TableColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            buffer_bg: tailwind::SLATE.c950,
            header_bg: color.c900,
            header_fg: tailwind::SLATE.c200,
            row_fg: tailwind::SLATE.c200,
            selected_row_style_fg: color.c400,
            selected_column_style_fg: color.c400,
            selected_cell_style_fg: color.c600,
            normal_row_color: tailwind::SLATE.c950,
            alt_row_color: tailwind::SLATE.c900,
            help_border_color: color.c400,
        }
    }
}

pub struct HostsTable<'a> {
    items: &'a Vec<Host>,
    longest_item_lens: (u16, u16, u16, u16, u16), // order is (name, address, email)
    colors: TableColors,
    color_index: usize,
}

impl<'a> HostsTable<'a> {
    pub fn new(data_vec: &'a Vec<Host>) -> Self {
        Self {
            longest_item_lens: Self::constraint_len_calculator(data_vec),
            colors: TableColors::new(&PALETTES[0]),
            color_index: 0,
            items: data_vec,
        }
    }

    pub fn set_colors(&mut self) {
        self.colors = TableColors::new(&PALETTES[self.color_index]);
    }

    pub fn draw(
        &mut self,
        table_state: &mut TableState,
        scroll_state: &mut ScrollbarState,
        frame: &mut Frame,
        area: Rect,
    ) {
        let vertical = &Layout::vertical([Constraint::Min(5), Constraint::Length(4)]);
        let rects = vertical.split(area);

        self.set_colors();

        self.render_table(table_state, frame, rects[0]);
        self.render_scrollbar(scroll_state, frame, rects[0]);
        self.render_help(frame, rects[1]);
    }

    fn render_table(&mut self, table_state: &mut TableState, frame: &mut Frame, area: Rect) {
        let header_style = Style::default()
            .fg(self.colors.header_fg)
            .bg(self.colors.header_bg);
        let selected_row_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_row_style_fg);
        let selected_col_style = Style::default().fg(self.colors.selected_column_style_fg);
        let selected_cell_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_cell_style_fg);

        let header = ["IP Address", "Mac Address", "Speed ↓", "Speed ↑", "Time"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);
        let rows = self.items.iter().enumerate().map(|(i, host)| {
            let color = match i % 2 {
                0 => self.colors.normal_row_color,
                _ => self.colors.alt_row_color,
            };
            let row = [
                host.ipv4.to_string(),
                {
                    if host.is_my_device_mac {
                        host.mac.to_string() + " (*)"
                    } else {
                        host.mac.to_string()
                    }
                },
                {
                    if let Some(speed) = host.speed {
                        speed.to_string_input()
                    } else {
                        String::from("")
                    }
                },
                {
                    if let Some(speed) = host.speed {
                        speed.to_string_output()
                    } else {
                        String::from("")
                    }
                },
                {
                    let diff = Local::now().timestamp_millis() - host.time.timestamp_millis();
                    let durr =
                        Duration::new(diff / 1000, (diff % 1000) as u32 * 1000).unwrap_or_default();
                    format!(
                        "{:2} min {:2} sec ago",
                        durr.num_minutes(),
                        durr.num_seconds() - (durr.num_minutes() * 60)
                    )
                }, // data.time.to_string(),
            ];
            row.into_iter()
                .map(|content| Cell::from(Text::from(content)))
                .collect::<Row>()
                .style(Style::new().fg(self.colors.row_fg).bg(color))
                .height(1)
        });
        let bar = " ━ ";
        let table = Table::new(
            rows,
            [
                // + 1 is for padding.
                Constraint::Length(self.longest_item_lens.0 + 1),
                Constraint::Min(self.longest_item_lens.1 + 4),
                Constraint::Min(self.longest_item_lens.2),
                Constraint::Min(self.longest_item_lens.3),
                Constraint::Min(self.longest_item_lens.4),
            ],
        )
        .header(header)
        .row_highlight_style(selected_row_style)
        .column_highlight_style(selected_col_style)
        .cell_highlight_style(selected_cell_style)
        .highlight_symbol(Text::from(vec![bar.into()]))
        .bg(self.colors.buffer_bg)
        .highlight_spacing(HighlightSpacing::Always);
        frame.render_stateful_widget(table, area, table_state);
    }

    fn render_scrollbar(
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

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let info_help = Paragraph::new(Text::from_iter(INFO_TEXT))
            .style(
                Style::new()
                    .fg(self.colors.row_fg)
                    .bg(self.colors.buffer_bg),
            )
            .centered()
            .block(
                Block::bordered()
                    .border_type(BorderType::Double)
                    .border_style(Style::new().fg(self.colors.help_border_color)),
            );
        frame.render_widget(info_help, area);
    }

    fn constraint_len_calculator(items: &[Host]) -> (u16, u16, u16, u16, u16) {
        let ip_len = items
            .iter()
            .map(|h| h.ipv4.to_string().len())
            .max()
            .unwrap_or(0);
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
        let time_len = items
            .iter()
            .map(|h| h.time.to_string().len())
            .max()
            .unwrap_or(0);

        #[allow(clippy::cast_possible_truncation)]
        (
            ip_len as u16,
            mac_len as u16,
            speed_down_len as u16,
            speed_up_len as u16,
            time_len as u16,
        )
    }
}
