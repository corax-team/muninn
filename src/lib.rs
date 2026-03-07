pub mod model;
pub mod parsers;
pub mod search;
pub mod sigma;

pub use model::{Event, ParseResult, SourceFormat};
pub use parsers::{detect_format, discover_files, parse_file, parse_file_as, parse_files_parallel};
pub use search::{SearchEngine, SearchResult};
pub use sigma::{compile, load_rules, Rule};
