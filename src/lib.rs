pub mod model;
pub mod parsers;
pub mod search;
pub mod sigma;

pub mod anomaly;
pub mod correlate;
pub mod diff;
pub mod hunt;
pub mod ioc;
pub mod login;
pub mod mitre;
pub mod output;
pub mod scoring;
pub mod summary;
pub mod timeline;
pub mod transforms;

pub use model::{Event, ParseResult, SourceFormat};
pub use parsers::{detect_format, discover_files, parse_file, parse_file_as, parse_files_parallel};
pub use search::{SearchEngine, SearchResult};
pub use sigma::{compile, load_rules, EventFilter, Rule};

#[cfg(feature = "download")]
pub mod download;

#[cfg(feature = "tui")]
pub mod tui;

#[cfg(feature = "ioc-enrich")]
pub mod opentip;

#[cfg(feature = "live")]
pub mod live;
