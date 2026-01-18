use std::io;

use logging::initialize_logging;
use ratatui::{backend::CrosstermBackend, Terminal};
use scanner::Scanner;

use crate::{
    app::{App, AppResult},
    backend::BackendType,
    event::{Event, EventHandler},
    tui::Tui,
};

pub mod app;
pub mod backend;
pub mod event;
pub mod hosts_table;
pub mod logging;
pub mod scanner;
pub mod stats_aggregator;
pub mod tui;
pub mod types;
pub mod ui;

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the interface to watch
    #[arg(short, long)]
    name: String,
    /// Backend to use for packet capture
    #[arg(long, short = 'b', default_value_t, value_enum)]
    backend: BackendType,
}

#[tokio::main]
async fn main() -> AppResult<()> {
    let args = Args::parse();
    let interface_name = args.name;

    initialize_logging()?;

    // Initialize the terminal user interface.
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;
    let mut tui = Tui::new(terminal);

    // IMPORTANT: Initialize terminal (raw mode) BEFORE creating EventHandler,
    // because EventStream requires the terminal to be in raw mode.
    tui.init()?;

    let mut events = EventHandler::new(250);
    let scanner = Scanner::new(events.get_sender_clone(), interface_name, args.backend)?;

    // Create an application.
    let mut app = App::new(scanner)?;
    // Start the main loop.
    while app.running {
        // Render the user interface.
        tui.draw(&mut app)?;
        // Handle events.
        match events.next().await? {
            Event::Tick => app.tick(),
            Event::Key(key_event) => app.handle_key_events(key_event)?,
            Event::Mouse(_) => {}
            Event::Resize(_, _) => {}
            Event::Scanner(worker_event) => app.handle_worker_events(worker_event)?,
        }
    }

    // Exit the user interface.
    // Explicitly drop the scanner before exiting the TUI to ensure
    // background tasks are cancelled before terminal restoration
    drop(app);
    tui.exit()?;
    Ok(())
}
