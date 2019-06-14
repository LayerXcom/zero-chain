/// Configuration about color printed out to your terminal screen.
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

/// Configuration for the output options
pub struct Config {
    pub color: ColorChoice,
    pub quiet: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            color: ColorChoice::Auto,
            quiet: false,
        }
    }
}
