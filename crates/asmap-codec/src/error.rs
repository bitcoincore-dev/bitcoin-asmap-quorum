//! Typed errors for the ASMap codec.
//!
//! The messages (and the `source` chains behind them) are byte-for-byte the
//! ones the single-crate CLI produced through `anyhow`, so `{err:#}` rendering
//! in the binary is unchanged.

use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;

use thiserror::Error;

/// Failure parsing an `ADDR/LEN` network prefix.
#[derive(Debug, Error)]
pub enum ParseNetworkError {
    /// The text is not `ADDR/LEN`, or the prefix length is out of range.
    #[error("invalid network '{network}'")]
    Invalid {
        /// The offending input.
        network: String,
    },
    /// The address half did not parse.
    #[error("invalid network '{network}'")]
    InvalidAddr {
        /// The offending input.
        network: String,
        /// The underlying address parse failure.
        #[source]
        source: AddrParseError,
    },
    /// The prefix-length half did not parse.
    #[error("invalid network '{network}'")]
    InvalidPrefixLen {
        /// The offending input.
        network: String,
        /// The underlying integer parse failure.
        #[source]
        source: ParseIntError,
    },
}

/// Failure counting the addresses covered by a network prefix.
#[derive(Debug, Error)]
pub enum NetworkCountError {
    /// The text has no `/LEN` suffix.
    #[error("invalid network '{network}'")]
    Invalid {
        /// The offending input.
        network: String,
    },
    /// The prefix length did not parse.
    #[error(transparent)]
    PrefixLen(#[from] ParseIntError),
}

/// Failure loading an ASMap from text or binary input.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The input stream could not be read.
    #[error("Input file '{input_name}' cannot be read")]
    Read {
        /// Display name of the input.
        input_name: String,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// The input decodes as both binary and text.
    #[error("Input file '{input_name}' is ambiguous.")]
    Ambiguous {
        /// Display name of the input.
        input_name: String,
    },
    /// The input decodes as neither binary nor text.
    #[error(
        "Input file '{input_name}' is neither a valid binary asmap file nor valid text input ({reason})"
    )]
    Unrecognized {
        /// Display name of the input.
        input_name: String,
        /// Why the text parse failed.
        reason: String,
    },
}

/// Failure writing an ASMap out as text or binary.
#[derive(Debug, Error)]
#[error("Output file '{output_name}' cannot be written to")]
pub struct SaveError {
    /// Display name of the output.
    pub output_name: String,
    /// The underlying I/O failure.
    #[source]
    pub source: io::Error,
}

impl SaveError {
    pub(crate) fn new(output_name: &str, source: io::Error) -> Self {
        Self {
            output_name: output_name.to_string(),
            source,
        }
    }
}
