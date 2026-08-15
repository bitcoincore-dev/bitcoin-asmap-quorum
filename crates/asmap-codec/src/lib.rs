//! ASMap codec: the prefix trie, Bitcoin Core's binary encoding, and the
//! text/binary file formats used by `bitcoin-asmap-quorum`.
//!
//! This crate is deliberately dependency-light — `std`, `thiserror`, and an
//! optional `serde` feature (on by default) that adds `Serialize`/`Deserialize`
//! to [`ASMap`]. It carries no networking, async runtime, or CLI machinery.
//!
//! The vendored Python reference implementation in `contrib/asmap/asmap.py` at
//! the repository root remains the authority on correct behaviour.

#![deny(missing_docs)]

mod coder;
pub mod error;
mod io;
mod net;
#[cfg(feature = "testgen")]
pub mod testgen;
mod trie;

pub use crate::error::{LoadError, NetworkCountError, ParseNetworkError, SaveError};
pub use crate::io::{load_file, save_binary, save_text};
pub use crate::net::{
    ASNDiff, ASNEntry, bits_to_network, ip_to_bits, network_address_count, parse_network_prefix,
};
pub use crate::trie::ASMap;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn network_roundtrip_ipv4() {
        let bits = ip_to_bits("1.2.3.0".parse::<IpAddr>().unwrap(), 24);
        assert_eq!(bits_to_network(&bits), "1.2.3.0/24");
    }

    #[test]
    fn network_roundtrip_ipv6() {
        let bits = ip_to_bits("2001:db8::".parse::<IpAddr>().unwrap(), 32);
        assert_eq!(bits_to_network(&bits), "2001:db8::/32");
    }

    #[test]
    fn binary_roundtrip_empty() {
        let state = ASMap::new();
        let enc = state.to_binary(false);
        let dec = ASMap::from_binary(&enc).unwrap();
        assert_eq!(state, dec);
    }
}
