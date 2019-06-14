use console::{self, set_colors_enabled};
use super::config::ColorChoice;

pub struct Style {
    pub error: console::Style,
    pub warning: console::Style,
    pub success: console::Style,
    pub info: console::Style,
}

impl Style {
    pub fn new(color_choice: &ColorChoice) -> Self {
        match color_choice {
            ColorChoice::Auto => {},
            ColorChoice::Never => set_colors_enabled(false),
            ColorChoice::Always => set_colors_enabled(true),
        };

        Style {
            error: console::Style::new().red().bold(),
            warning: console::Style::new().red(),
            success: console::Style::new().green(),
            info: console::Style::new().cyan().italic(),
        }
    }
}