use console;
use dialoguer;
use std::{
    error::Error,
    io::{self, Write},
    ops,
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
    ) -> io::Result<Vec<u8>> {
        dialoguer::PasswordInput::new()
            .with_prompt(prompt)
            .with_confirmation(confirmation, mismatch_err)
            .interact()
            .map(|e| e.into_bytes())
    }

    pub fn passowrd(
        &mut self,
        prompt: &str,
    ) -> io::Result<Vec<u8>> {
        dialoguer::PasswordInput::new()
            .with_prompt(prompt)
            .interact()
            .map(|e| e.into_bytes())
    }

    pub fn account_name(
        &mut self,
        prompt: &str,
    ) -> io::Result<String> {
        dialoguer::Input::new()
            .with_prompt(prompt)
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
        let mut error: &dyn Error = &e;
        let formated = format!("{}", e);
        writeln!(&mut self.term, "{}", self.style.error.apply_to(formated)).unwrap();

        while let Some(err) = error.source() {
            error = err;
            let formated = format!("{}", err);
            writeln!(
                &mut self.term,
                "  |-> {}",
                self.style.warning.apply_to(formated)
            ).unwrap();
        }

        ::std::process::exit(1)
    }
}

impl io::Write for Term {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.term, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.term)
    }
}

impl io::Read for Term {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.term, buf)
    }
}

impl ops::Deref for Term {
    type Target = console::Term;

    fn deref(&self) -> &Self::Target {
        &self.term
    }
}

impl ops::DerefMut for Term {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.term
    }
}
