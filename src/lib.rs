//! ZUC Stream Cipher Algorithms

#![deny(unsafe_code, missing_docs)]
#![deny(clippy::all, clippy::pedantic, clippy::cargo)]
#![allow(clippy::inline_always)]
// ---
#![cfg_attr(docsrs, feature(doc_cfg))]

mod zuc128;
pub use self::zuc128::ZUC128;