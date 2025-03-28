use ratatui::prelude::*;
use ratatui::style::palette::tailwind;
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::hosts_table::HostsTable;

/// Renders the user interface widgets.
pub fn render(app: &mut App, frame: &mut Frame) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![
            Constraint::Percentage(100),
            // Constraint::Percentage(50),
            Constraint::Length(3),
        ]);
    if let [table_area, 
    // middle_area,
    footer_area] = *layout.split(frame.area()) {
        render_hosts_table(frame, table_area, app);
        render_footer(frame, footer_area, app);
        // render_middle(frame, middle_area, app);
    }
}

fn _render_middle(frame: &mut Frame<'_>, middle_area: Rect, app: &mut App) {
    let items = app.stats_aggregator.connections_strs();
    // frame.render_widget(Text::from(items.len().to_string()), middle_area);
    let paragraph = Paragraph::new(Text::from_iter(items)).block(Block::new().title("connections"));
    frame.render_widget(paragraph, middle_area);
}

fn render_hosts_table(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let mut hosts_table = HostsTable::new(&app.hosts);
    hosts_table.draw(&mut app.table_state, &mut app.scroll_state, frame, area);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(5),
        ])
        .split(area);
    let state = if app.sending_arps {
        "Sending ARPs"
    } else {
        "Idle"
    };
    render_widget(frame, "State", state, layout[0]);
    render_widget(
        frame,
        "Number of hosts",
        app.hosts.len().to_string().as_str(),
        layout[1],
    );
    render_widget(frame, "Interface", &app.interface, layout[2]);
    render_widget(frame, "Speed", &app.stats_aggregator.speed_str(), layout[3]);
}

fn render_widget(frame: &mut Frame, title: &str, content: &str, area: Rect) {
    let style = Style::new().fg(tailwind::BLUE.c400);
    frame.render_widget(
        Paragraph::new(content).centered().block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(style)
                .title(title),
        ),
        area,
    );
}
