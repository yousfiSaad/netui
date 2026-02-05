use std::path::PathBuf;
use std::sync::OnceLock;

use directories::ProjectDirs;
use tracing_error::ErrorLayer;
use tracing_subscriber::{self, layer::SubscriberExt, util::SubscriberInitExt, Layer};

use netui::error::AppResult;

/// Global constants initialized once at runtime.
fn get_project_name() -> &'static String {
    static PROJECT_NAME: OnceLock<String> = OnceLock::new();
    PROJECT_NAME.get_or_init(|| env!("CARGO_CRATE_NAME").to_uppercase().to_string())
}

fn get_data_folder() -> &'static Option<PathBuf> {
    static DATA_FOLDER: OnceLock<Option<PathBuf>> = OnceLock::new();
    DATA_FOLDER.get_or_init(|| {
        std::env::var(format!("{}_DATA", get_project_name()))
            .ok()
            .map(PathBuf::from)
    })
}

fn get_log_env() -> &'static String {
    static LOG_ENV: OnceLock<String> = OnceLock::new();
    LOG_ENV.get_or_init(|| format!("{}_LOGLEVEL", get_project_name()))
}

fn get_log_file() -> &'static String {
    static LOG_FILE: OnceLock<String> = OnceLock::new();
    LOG_FILE.get_or_init(|| format!("{}.log", env!("CARGO_PKG_NAME")))
}

fn project_directory() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "kdheepak", env!("CARGO_PKG_NAME"))
}

pub fn get_data_dir() -> PathBuf {
    let directory = if let Some(s) = get_data_folder().clone() {
        s
    } else if let Some(proj_dirs) = project_directory() {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".data")
    };
    directory
}

pub fn initialize_logging() -> AppResult<()> {
    let directory = get_data_dir();
    std::fs::create_dir_all(directory.clone())?;
    let log_path = directory.join(get_log_file().clone());
    let log_file = std::fs::File::create(log_path)?;
    std::env::set_var(
        "RUST_LOG",
        std::env::var("RUST_LOG")
            .or_else(|_| std::env::var(get_log_env().clone()))
            .unwrap_or_else(|_| format!("{}=info", env!("CARGO_CRATE_NAME"))),
    );
    let file_subscriber = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_writer(log_file)
        .with_target(false)
        .with_ansi(false)
        .with_filter(tracing_subscriber::filter::EnvFilter::from_default_env());
    tracing_subscriber::registry()
        .with(file_subscriber)
        .with(ErrorLayer::default())
        .init();
    Ok(())
}

/// Similar to the `std::dbg!` macro, but generates `tracing` events rather
/// than printing to stdout.
///
/// By default, the verbosity level for the generated events is `DEBUG`, but
/// this can be customized.
#[macro_export]
macro_rules! trace_dbg {
    (target: $target:expr, level: $level:expr, $ex:expr) => {{
        match $ex {
            value => {
                tracing::event!(target: $target, $level, ?value, stringify!($ex));
                value
            }
        }
    }};
    (level: $level:expr, $ex:expr) => {
        trace_dbg!(target: module_path!(), level: $level, $ex)
    };
    (target: $target:expr, $ex:expr) => {
        trace_dbg!(target: $target, level: tracing::Level::DEBUG, $ex)
    };
    ($ex:expr) => {
        trace_dbg!(level: tracing::Level::DEBUG, $ex)
    };
}
