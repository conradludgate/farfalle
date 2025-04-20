use digest::core_api::{ExtendableOutputCore, UpdateCore};
use digest::crypto_common::KeyInit;

pub trait DeckCore: ExtendableOutputCore + UpdateCore + KeyInit {}
impl<F> DeckCore for F where F: ExtendableOutputCore + KeyInit + UpdateCore {}
