//! Conversions between textual network prefixes and ASMap prefix bit paths.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{NetworkCountError, ParseNetworkError};

/// A single `prefix bits -> ASN` assignment.
pub type ASNEntry = (Vec<bool>, u32);
/// A single `prefix bits -> (old ASN, new ASN)` change.
pub type ASNDiff = (Vec<bool>, u32, u32);

/// Parses `ADDR/LEN` into an address and prefix length.
///
/// Strict, like Python's `ipaddress.ip_network(..., strict=True)`: a prefix with
/// host bits set (`1.2.3.4/8`) is rejected rather than silently truncated to
/// `1.0.0.0/8`.
pub fn parse_network_prefix(input: &str) -> Result<(IpAddr, u8), ParseNetworkError> {
    let (addr, prefix) = input
        .split_once('/')
        .ok_or_else(|| ParseNetworkError::Invalid {
            network: input.to_string(),
        })?;
    let ip: IpAddr = addr
        .parse()
        .map_err(|source| ParseNetworkError::InvalidAddr {
            network: input.to_string(),
            source,
        })?;
    let prefix_len: u8 = prefix
        .parse()
        .map_err(|source| ParseNetworkError::InvalidPrefixLen {
            network: input.to_string(),
            source,
        })?;
    let width: u8 = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > width {
        return Err(ParseNetworkError::Invalid {
            network: input.to_string(),
        });
    }
    if !is_canonical(ip, prefix_len) {
        return Err(ParseNetworkError::Invalid {
            network: input.to_string(),
        });
    }
    Ok((ip, prefix_len))
}

/// True when `ip` has no bits set below its `prefix_len` boundary.
///
/// `trailing_zeros()` of zero is the full width, so `/0` and the all-zero
/// address are handled without a shift-overflow special case.
fn is_canonical(ip: IpAddr, prefix_len: u8) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            u32::from(v4).trailing_zeros() >= u32::from(32u8.saturating_sub(prefix_len))
        }
        IpAddr::V6(v6) => {
            u128::from_be_bytes(v6.octets()).trailing_zeros()
                >= u32::from(128u8.saturating_sub(prefix_len))
        }
    }
}

/// Expands an address plus prefix length to the ASMap prefix bit path.
///
/// Host bits below the prefix boundary are discarded. Callers are expected to
/// have gone through [`parse_network_prefix`] (or to be passing a full-length
/// prefix); the `debug_assert!` mirrors the belt-and-braces assertion in
/// `net_to_prefix` in `contrib/asmap/asmap.py`, which treats a non-canonical
/// prefix as a programming error rather than a validation path.
pub fn ip_to_bits(ip: IpAddr, prefix_len: u8) -> Vec<bool> {
    debug_assert!(
        is_canonical(ip, prefix_len),
        "ip_to_bits called with host bits set: {ip}/{prefix_len}"
    );
    let (netrange, num_bits) = match ip {
        IpAddr::V4(v4) => (
            (u32::from(v4) as u128) + 0xffff_0000_0000u128,
            prefix_len as usize + 96,
        ),
        IpAddr::V6(v6) => (u128::from_be_bytes(v6.octets()), prefix_len as usize),
    };
    (0..num_bits)
        .map(|i| ((netrange >> (127 - i)) & 1) != 0)
        .collect()
}

/// Renders a prefix bit path back to `ADDR/LEN` text.
pub fn bits_to_network(prefix: &[bool]) -> String {
    let netrange = prefix.iter().enumerate().fold(0u128, |acc, (i, bit)| {
        if *bit {
            acc | (1u128 << (127 - i))
        } else {
            acc
        }
    });
    if prefix.len() >= 96 && (netrange >> 32) == 0xffff {
        let addr = Ipv4Addr::from((netrange & 0xffff_ffff) as u32);
        format!("{addr}/{}", prefix.len() - 96)
    } else {
        format!("{}/{}", Ipv6Addr::from(netrange), prefix.len())
    }
}

/// Counts the addresses covered by a textual network prefix.
pub fn network_address_count(net: &str) -> Result<u128, NetworkCountError> {
    let (_, prefix_len) = net
        .rsplit_once('/')
        .ok_or_else(|| NetworkCountError::Invalid {
            network: net.to_string(),
        })?;
    let prefix_len: u32 = prefix_len.parse()?;
    if net.contains('.') {
        Ok(1u128 << (32 - prefix_len))
    } else {
        Ok(1u128.checked_shl(128 - prefix_len).unwrap_or(u128::MAX))
    }
}
