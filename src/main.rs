use std::io;

use logging::initialize_logging;
use ratatui::{backend::CrosstermBackend, Terminal};
use scanner::Scanner;

use crate::{
    app::{App, AppResult},
    event::{Event, EventHandler},
    tui::Tui,
};

pub mod app;
pub mod event;
pub mod hosts_table;
pub mod logging;
pub mod scanner;
pub mod stats_aggregator;
pub mod tui;
pub mod ui;

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the interface to watch
    #[arg(short, long)]
    name: String,
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
    let mut events = EventHandler::new(250);
    let scanner = Scanner::new(events.get_sender_clone(), interface_name)?;

    // Create an application.
    let mut app = App::new(scanner)?;

    tui.init()?;
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
    tui.exit()?;
    Ok(())
}
