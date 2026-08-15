//! Reading and writing ASMaps in the text and binary on-disk formats.

use std::io::{Read, Write};

use crate::error::{LoadError, SaveError};
use crate::net::{ASNEntry, bits_to_network, ip_to_bits, parse_network_prefix};
use crate::trie::ASMap;

/// Loads an ASMap from a stream, auto-detecting text vs. binary encoding.
pub fn load_file(mut input: Box<dyn Read>, input_name: &str) -> Result<ASMap, LoadError> {
    let mut contents = Vec::new();
    input
        .read_to_end(&mut contents)
        .map_err(|source| LoadError::Read {
            input_name: input_name.to_string(),
            source,
        })?;

    let bin_asmap = ASMap::from_binary(&contents);
    let mut txt_error = None;
    let mut entries: Option<Vec<ASNEntry>> = None;

    if let Ok(txt_contents) = std::str::from_utf8(&contents) {
        // `entries` must mean exactly what Python's `entries is not None` means:
        // `Some` iff the *whole* text parse succeeded. Every per-line failure is
        // SOFT — it records a message and leaves the binary interpretation as the
        // remaining candidate — so none of these may escape via `?`.
        //
        // Two lexer divergences from asmap-tool.py remain here, both pre-existing
        // and deliberately out of scope: Python splits with `line.split(' ')` and
        // requires exactly 2 fields, so a tab-separated line is "unparseable"
        // where `split_whitespace()` accepts it; and Python trims
        // `lstrip(' ').rstrip(' \t\r\n')` where this uses `trim()`.
        let parse_text = || -> Result<Vec<ASNEntry>, String> {
            let mut parsed = Vec::new();
            for line in txt_contents.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                let mut fields = line.split_whitespace();
                let prefix = fields.next();
                let asn = fields.next();
                if prefix.is_none() || asn.is_none() || fields.next().is_some() {
                    return Err(format!("unparseable line '{line}'"));
                }
                let (prefix, asn) = (prefix.unwrap(), asn.unwrap());
                if !asn.starts_with("AS")
                    || asn.len() <= 2
                    || !asn[2..].chars().all(|c| c.is_ascii_digit())
                {
                    return Err(format!("invalid ASN '{asn}'"));
                }
                let net = parse_network_prefix(prefix)
                    .map_err(|_| format!("invalid network '{prefix}'"))?;
                // The digit check above already ran, so this only fails on
                // overflow.
                let asn_value: u32 = asn[2..]
                    .parse()
                    .map_err(|_| format!("invalid ASN '{asn}'"))?;
                parsed.push((ip_to_bits(net.0, net.1), asn_value));
            }
            Ok(parsed)
        };
        match parse_text() {
            Ok(parsed) => entries = Some(parsed),
            Err(message) => {
                txt_error = Some(message);
                entries = None;
            }
        }
    } else {
        txt_error = Some("invalid UTF-8".to_string());
    }

    if entries.is_some() && bin_asmap.is_some() && !contents.is_empty() {
        return Err(LoadError::Ambiguous {
            input_name: input_name.to_string(),
        });
    }
    if let Some(entries) = entries {
        let mut state = ASMap::new();
        state.update_multi(entries);
        return Ok(state);
    }
    if let Some(state) = bin_asmap {
        return Ok(state);
    }
    Err(LoadError::Unrecognized {
        input_name: input_name.to_string(),
        reason: txt_error.unwrap_or_else(|| "unparseable".to_string()),
    })
}

/// Writes the ASMap in Bitcoin Core's binary format.
pub fn save_binary(
    mut output: Box<dyn Write>,
    state: &ASMap,
    fill: bool,
    output_name: &str,
) -> Result<(), SaveError> {
    let contents = state.to_binary(fill);
    output
        .write_all(&contents)
        .map_err(|source| SaveError::new(output_name, source))?;
    Ok(())
}

/// Writes the ASMap as `NETWORK ASN` text lines.
pub fn save_text(
    mut output: Box<dyn Write>,
    state: &ASMap,
    fill: bool,
    overlapping: bool,
    output_name: &str,
) -> Result<(), SaveError> {
    for (prefix, asn) in state.to_entries(fill, overlapping) {
        let net = bits_to_network(&prefix);
        writeln!(output, "{net} AS{asn}").map_err(|source| SaveError::new(output_name, source))?;
    }
    Ok(())
}
