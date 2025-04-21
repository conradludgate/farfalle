use digest::{core_api::{ExtendableOutputCore, UpdateCore}, Update, XofReader};

/// Block-based core impl for Doubly-Extendable Cryptographic ([`Dec`]) functions.
pub trait DecCore: ExtendableOutputCore + UpdateCore + Default {}

/// Trait for Doubly-Extendable Cryptographic (dec) functions.
///
/// These are like extendable output ([`XOF`](digest::ExtendableOutput)) functions,
/// except they are explicitly designed to support further updates of the state after finalization.
pub trait Dec: Update {
    /// Reader
    type Reader: XofReader;

    /// Finalize the updates, retrieve XOF reader, and update the dec state.
    fn finalize_dec(&mut self) -> Self::Reader;
}
