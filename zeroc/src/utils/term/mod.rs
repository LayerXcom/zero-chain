
use console;

mod config;
mod style;
pub use self::config::{ColorChoice, Config};
pub use self::style::Style;

pub struct Term {
    pub config: Config,
    pub style: Style,
    pub term: console::Term,
}

impl Term {
    pub fn new(config: Config) -> Self {
        if !console::user_attended() {
            warn!("There might be issue with non user attended terminal.")
        }

        let term = console::Term::stdout();
        let style = Style::new(&config.color);

        Term {
            config,
            style,
            term,
        }
    }
}
