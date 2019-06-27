use console;
use dialoguer;
use std::{
    error::Error,
    io::{self, Write},
};

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

    pub fn new_password(
        &mut self,
        prompt: &str,
        confirmation: &str,
        mismatch_err: &str
    ) -> io::Result<String> {
        dialoguer::PasswordInput::new()
            .with_prompt(prompt)
            .with_confirmation(confirmation, mismatch_err)
            .interact()
    }

    pub fn simply(&mut self, msg: &str) -> io::Result<()> {
        write!(self, "{}", msg)
    }

    pub fn success(&mut self, msg: &str) -> io::Result<()> {
        write!(&mut self.term, "{}", self.style.success.apply_to(msg))
    }

    pub fn info(&mut self, msg: &str) -> io::Result<()> {
        write!(&mut self.term, "{}", self.style.info.apply_to(msg))
    }
    pub fn warn(&mut self, msg: &str) -> io::Result<()> {
        write!(&mut self.term, "{}", self.style.warning.apply_to(msg))
    }

    pub fn error(&mut self, msg: &str) -> io::Result<()> {
        write!(&mut self.term, "{}", self.style.error.apply_to(msg))
    }

    pub fn fail_with<E>(&mut self, e: E) -> !
    where
        E: Error,
    {
        let mut error: &Error = &e;
        let formated = format!("{}", e);
        writeln!(&mut self.term, "{}", self.style.error.apply_to(formated));

        while let Some(err) = error.source() {
            error = err;
            let formated = format!("{}", err);
            writeln!(
                &mut self.term,
                "  |-> {}",
                self.style.warning.apply_to(formated)
            );
        }

        ::std::process::exit(1)
    }
}
