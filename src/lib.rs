#![crate_type = "lib"]
#![crate_name = "baozi"]

extern crate num;
extern crate rand;

#[macro_use]
extern crate enum_primitive;

pub use client::TlsClient;

#[macro_use]
pub mod macros;
pub mod util;

// basic crypto primitives
pub mod crypto;

pub mod tls_result;
#[macro_use]
pub mod tls_item;

// TLS AEAD cipehrsuites
pub mod cipher;

pub mod alert;
pub mod handshake;
pub mod signature;

pub mod client;
pub mod tls;

#[cfg(test)]
mod test;
