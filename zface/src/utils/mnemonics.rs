use bip39::{Language, Mnemonic, MnemonicType};
use console::style;
use dialoguer::{Confirmation, Input};

pub fn input_mnemonic_phrase(mnemonic_type: MnemonicType, lang: Language) -> Mnemonic {
    let count = mnemonic_type.word_count();

    loop {
        let phrase_str: String = Input::new()
            .with_prompt(&format!(
                "Please enter all your {} mnemonics",
                style(count).bold().red()
            ))
            .interact()
            .unwrap();

        match Mnemonic::validate(phrase_str.as_str(), lang) {
            Ok(_) => {
                return Mnemonic::from_phrase(phrase_str, lang).unwrap();
            }
            Err(prompt) => {
                while !Confirmation::new()
                    .with_text(&prompt.to_string())
                    .default(true)
                    .show_default(true)
                    .interact()
                    .unwrap()
                {}
            }
        }
    }
}
