pub mod components;
pub mod theme;

use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style, Stylize},
    widgets::{Block, Clear, Paragraph},
    Frame,
};

use crate::tui_mod::app::{App, ViewMode};
use crate::tui_mod::ui::components::{
    apps::Apps, connections::Connections, footer::Footer, help::HelpModal, hosts_table::HostsTable,
    tabs::Tabs,
};
use crate::tui_mod::ui::theme::Theme;
use netui::constants::{FOOTER_HEIGHT, MIN_TERMINAL_HEIGHT, MIN_TERMINAL_WIDTH, TAB_HEIGHT};

/// Renders the user interface widgets.
pub fn render(app: &mut App, frame: &mut Frame) {
    let theme = Theme::default();

    // Check minimum terminal size
    let area = frame.area();
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        let error = Paragraph::new(format!(
            "Terminal too small!\n\nMinimum: {}x{}",
            MIN_TERMINAL_WIDTH, MIN_TERMINAL_HEIGHT
        ))
        .style(Style::new().fg(Color::Red).bold())
        .centered();
        frame.render_widget(error, area);
        return;
    }

    // 1. Clear the entire frame to ensure a clean slate
    frame.render_widget(Clear, frame.area());

    // 2. Render a background block for the whole application
    let background_block = Block::default().style(theme.app_block());
    frame.render_widget(background_block, frame.area());

    // 3. Render help modal overlay if visible
    if app.help_visible {
        let help_modal = HelpModal { visible: true };
        help_modal.render(frame, frame.area());
        return;
    }

    // 4. Define layout
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![
            Constraint::Length(TAB_HEIGHT),
            Constraint::Min(0),
            Constraint::Length(FOOTER_HEIGHT),
        ]);

    // Split the area
    if let [tabs_area, main_area, footer_area] = *layout.split(frame.area()) {
        // Render Tabs
        let tabs = Tabs::new(app.view_mode, &theme);
        tabs.render(frame, tabs_area);

        // Render Main Content
        match app.view_mode {
            ViewMode::Hosts => {
                let mut hosts_table = HostsTable::new(
                    &app.hosts,
                    &app.new_hosts,
                    &app.mac_changed_hosts,
                    &app.local_ips,
                    &app.stats_aggregator,
                    &theme,
                );

                hosts_table.render_table(&mut app.table_state, frame, main_area);
                hosts_table.render_scrollbar(&mut app.scroll_state, frame, main_area);
            }
            ViewMode::Connections => {
                // Get connection data, registry, and quality metrics first (to avoid holding app reference)
                let connections_data = app.stats_aggregator.connections_with_details();
                let num_connections = connections_data.len();
                let app_registry = app.stats_aggregator.app_registry();
                let quality_metrics = app.stats_aggregator.quality_metrics();

                // Create connections component
                let mut connections = Connections::new(&theme);

                // Render table with cloned data, registry, and quality metrics
                connections.render_table(
                    &connections_data,
                    &app_registry,
                    &quality_metrics,
                    &mut app.table_state,
                    frame,
                    main_area,
                );

                // Render scrollbar
                connections.render_scrollbar(
                    &mut app.scroll_state,
                    frame,
                    main_area,
                    num_connections,
                );
            }
            ViewMode::Apps => {
                let apps_stats = app.stats_aggregator.apps_stats();
                let apps = Apps::new(&theme);
                apps.render(frame, main_area, &mut app.table_state, apps_stats);
            }
        }

        // Render Footer
        let footer = Footer::new(app, &theme);
        footer.render(frame, footer_area);
    }
}
