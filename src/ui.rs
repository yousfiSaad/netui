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

        // Render help overlay if help is shown
        if app.show_help {
            render_help(frame);
        }
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

fn render_help(frame: &mut Frame) {
    let help_text = vec![
        "NetUI - Network Interface Monitor",
        "",
        "KEYBINDINGS:",
        "  q, ESC       - Quit application",
        "  Ctrl+C       - Quit application",
        "  ?, F1        - Show/hide this help",
        "",
        "  s            - Send ARP packets (scan network)",
        "  j            - Navigate down (vim-style)",
        "  k            - Navigate up (vim-style)",
        "  h            - Navigate left (vim-style)",
        "  l            - Navigate right (vim-style)",
        "  c, C         - Clean selected host and older entries",
        "",
        "FEATURES:",
        "  • Real-time network monitoring",
        "  • ARP host discovery",
        "  • Bandwidth tracking per host",
        "  • Upload/Download speed display",
        "",
        "Press any key to close this help...",
    ];

    // Center the help popup
    let area = centered_rect(60, 60, frame.area());

    // Create the help paragraph
    let paragraph = Paragraph::new(help_text.join("\n"))
        .block(
            Block::bordered()
                .title(" Help ")
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(tailwind::GREEN.c400))
        )
        .style(Style::default().bg(tailwind::SLATE.c950))
        .alignment(Alignment::Left);

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(paragraph, area);
}

/// Create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
