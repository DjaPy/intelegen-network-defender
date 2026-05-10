//! TLS ClientHello parsing and JA3/JA4 fingerprint computation

use md5::Md5;
use sha2::{Digest, Sha256};

/// Returns true if value is a GREASE value per RFC 8701.
/// Pattern: both bytes equal, lower nibble = 0xA (0x0A0A, 0x1A1A, ..., 0xFAFA)
fn is_grease_u16(v: u16) -> bool {
    let lo = (v & 0xFF) as u8;
    let hi = (v >> 8) as u8;
    lo == hi && (lo & 0x0F) == 0x0A
}

/// Raw data extracted from a TLS ClientHello message
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    pub client_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extension_types: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub alpn_first: Option<String>,
    pub sni: Option<String>,
}

/// TLS connection fingerprint (JA3 + JA4)
#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    /// JA3 hash — MD5 of the raw JA3 string
    pub ja3: String,
    /// Raw JA3 string before hashing
    pub ja3_string: String,
    /// JA4 fingerprint
    pub ja4: String,
    /// Server Name Indication from ClientHello
    pub sni: Option<String>,
}

impl TlsFingerprint {
    pub fn compute(info: &ClientHelloInfo) -> Self {
        let ja3_string = build_ja3_string(info);
        let ja3 = compute_md5_hex(ja3_string.as_bytes());
        let ja4 = build_ja4(info);
        Self {
            ja3,
            ja3_string,
            ja4,
            sni: info.sni.clone(),
        }
    }
}

/// JA3 = MD5("SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats")
/// Items within each field are `-` separated; fields are `,` separated.
fn build_ja3_string(info: &ClientHelloInfo) -> String {
    let ciphers: Vec<String> = info
        .cipher_suites
        .iter()
        .filter(|&&c| !is_grease_u16(c))
        .map(|c| c.to_string())
        .collect();

    let extensions: Vec<String> = info
        .extension_types
        .iter()
        .filter(|&&e| !is_grease_u16(e))
        .map(|e| e.to_string())
        .collect();

    let groups: Vec<String> = info
        .supported_groups
        .iter()
        .filter(|&&g| !is_grease_u16(g))
        .map(|g| g.to_string())
        .collect();

    let formats: Vec<String> = info
        .ec_point_formats
        .iter()
        .map(|f| f.to_string())
        .collect();

    format!(
        "{},{},{},{},{}",
        info.client_version,
        ciphers.join("-"),
        extensions.join("-"),
        groups.join("-"),
        formats.join("-"),
    )
}

fn compute_md5_hex(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// JA4 = t{version}_{ciphers:02}_{exts:02}_{alpn}_{cipher_hash:12}_{ext_hash:12}
fn build_ja4(info: &ClientHelloInfo) -> String {
    let tls_version = match info.client_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };

    let ciphers: Vec<u16> = info
        .cipher_suites
        .iter()
        .filter(|&&c| !is_grease_u16(c))
        .copied()
        .collect();

    // Extensions excluding GREASE, SNI (0x0000), ALPN (0x0010)
    let exts: Vec<u16> = info
        .extension_types
        .iter()
        .filter(|&&e| !is_grease_u16(e) && e != 0x0000 && e != 0x0010)
        .copied()
        .collect();

    let alpn = info
        .alpn_first
        .as_deref()
        .map(|s| if s.len() >= 2 { &s[..2] } else { s })
        .unwrap_or("00")
        .to_string();

    let cipher_count = ciphers.len();
    let mut sorted_ciphers = ciphers;
    sorted_ciphers.sort_unstable();
    let cipher_str = sorted_ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_hash = sha256_short(&cipher_str);

    let ext_count = exts.len();
    let mut sorted_exts = exts;
    sorted_exts.sort_unstable();
    let ext_str = sorted_exts
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash = sha256_short(&ext_str);

    format!(
        "t{}_{:02}_{:02}_{}_{}_{}",
        tls_version, cipher_count, ext_count, alpn, cipher_hash, ext_hash
    )
}

fn sha256_short(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let hex = hex::encode(result);
    hex[..12.min(hex.len())].to_string()
}

/// Parse a TLS ClientHello from raw bytes peeked from a TCP stream.
/// Returns `None` if the buffer is not a valid ClientHello or parsing fails.
pub fn parse_clienthello(buf: &[u8]) -> Option<ClientHelloInfo> {
    let mut pos = 0;

    // TLS record header: content_type(1) + version(2) + length(2)
    if buf.len() < 9 {
        return None;
    }
    if buf[pos] != 0x16 {
        return None;
    }
    pos += 3; // skip content_type + record_version

    let record_length = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if buf.len() < 5 + record_length {
        return None;
    }

    // Handshake header: msg_type(1) + length(3)
    if buf[pos] != 0x01 {
        return None; // Not a ClientHello
    }
    pos += 4; // skip msg_type + 3-byte length

    // client_version
    if pos + 2 > buf.len() {
        return None;
    }
    let client_version = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    // Skip random (32 bytes)
    pos += 32;
    if pos >= buf.len() {
        return None;
    }

    // Session ID
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if pos > buf.len() {
        return None;
    }

    // Cipher suites
    if pos + 2 > buf.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > buf.len() {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);
    for i in (0..cipher_suites_len).step_by(2) {
        cipher_suites.push(u16::from_be_bytes([buf[pos + i], buf[pos + i + 1]]));
    }
    pos += cipher_suites_len;

    // Compression methods
    if pos >= buf.len() {
        return None;
    }
    let compression_len = buf[pos] as usize;
    pos += 1 + compression_len;
    if pos > buf.len() {
        return None;
    }

    // Extensions are optional (e.g., SSLv3 has none)
    if pos + 2 > buf.len() {
        return Some(ClientHelloInfo {
            client_version,
            cipher_suites,
            extension_types: vec![],
            supported_groups: vec![],
            ec_point_formats: vec![],
            alpn_first: None,
            sni: None,
        });
    }

    let extensions_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + extensions_total_len).min(buf.len());

    let mut extension_types = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut alpn_first = None;
    let mut sni = None;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;
        let ext_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        if pos + ext_len > buf.len() {
            break;
        }
        let ext_data = &buf[pos..pos + ext_len];
        extension_types.push(ext_type);

        match ext_type {
            0x000A => parse_supported_groups(ext_data, &mut supported_groups),
            0x000B => parse_ec_point_formats(ext_data, &mut ec_point_formats),
            0x0010 => {
                alpn_first = parse_alpn_first(ext_data);
            }
            0x0000 => {
                sni = parse_sni(ext_data);
            }
            _ => {}
        }

        pos += ext_len;
    }

    Some(ClientHelloInfo {
        client_version,
        cipher_suites,
        extension_types,
        supported_groups,
        ec_point_formats,
        alpn_first,
        sni,
    })
}

fn parse_supported_groups(data: &[u8], groups: &mut Vec<u16>) {
    if data.len() < 2 {
        return;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = (2 + list_len).min(data.len());
    let mut i = 2;
    while i + 2 <= end {
        groups.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
}

fn parse_ec_point_formats(data: &[u8], formats: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    let formats_len = data[0] as usize;
    let end = (1 + formats_len).min(data.len());
    formats.extend_from_slice(&data[1..end]);
}

fn parse_alpn_first(data: &[u8]) -> Option<String> {
    // Format: list_len(2) + proto_len(1) + proto(...)
    if data.len() < 3 {
        return None;
    }
    let proto_len = data[2] as usize;
    if 3 + proto_len > data.len() {
        return None;
    }
    std::str::from_utf8(&data[3..3 + proto_len])
        .ok()
        .map(|s| s.to_string())
}

fn parse_sni(data: &[u8]) -> Option<String> {
    // Format: list_len(2) + name_type(1) + name_len(2) + name(...)
    if data.len() < 5 {
        return None;
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + name_len > data.len() {
        return None;
    }
    std::str::from_utf8(&data[5..5 + name_len])
        .ok()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_clienthello_bytes(
        version: u16,
        ciphers: &[u16],
        extensions: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut hello_body = Vec::new();

        // client_version
        hello_body.extend_from_slice(&version.to_be_bytes());
        // random (32 bytes)
        hello_body.extend_from_slice(&[0u8; 32]);
        // session_id (0 length)
        hello_body.push(0);
        // cipher suites
        let cipher_bytes: Vec<u8> = ciphers.iter().flat_map(|c| c.to_be_bytes()).collect();
        hello_body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&cipher_bytes);
        // compression methods (1 byte: 0x00)
        hello_body.push(1);
        hello_body.push(0);

        // extensions
        if !extensions.is_empty() {
            let mut ext_bytes = Vec::new();
            for (ext_type, ext_data) in extensions {
                ext_bytes.extend_from_slice(&ext_type.to_be_bytes());
                ext_bytes.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
                ext_bytes.extend_from_slice(ext_data);
            }
            hello_body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
            hello_body.extend_from_slice(&ext_bytes);
        }

        // Handshake header: ClientHello(0x01) + 3-byte length
        let hs_len = hello_body.len() as u32;
        let mut hs = vec![
            0x01,
            (hs_len >> 16) as u8,
            (hs_len >> 8) as u8,
            hs_len as u8,
        ];
        hs.extend_from_slice(&hello_body);

        // TLS record: Handshake(0x16) + version(0x0301) + length
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    fn supported_groups_ext(groups: &[u16]) -> Vec<u8> {
        let mut data = Vec::new();
        let inner: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
        data.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        data.extend_from_slice(&inner);
        data
    }

    fn ec_point_formats_ext(formats: &[u8]) -> Vec<u8> {
        let mut data = vec![formats.len() as u8];
        data.extend_from_slice(formats);
        data
    }

    #[test]
    fn test_parse_basic_clienthello() {
        let ciphers = &[0xC02Bu16, 0xC02F];
        let groups_data = supported_groups_ext(&[0x001Du16, 0x0017]);
        let formats_data = ec_point_formats_ext(&[0x00]);
        let extensions = vec![(0x000Au16, groups_data), (0x000Bu16, formats_data)];
        let buf = build_clienthello_bytes(0x0303, ciphers, &extensions);

        let info = parse_clienthello(&buf).expect("should parse");
        assert_eq!(info.client_version, 0x0303);
        assert_eq!(info.cipher_suites, vec![0xC02B, 0xC02F]);
        assert_eq!(info.supported_groups, vec![0x001D, 0x0017]);
        assert_eq!(info.ec_point_formats, vec![0x00]);
        assert_eq!(info.extension_types, vec![0x000A, 0x000B]);
    }

    #[test]
    fn test_grease_filtered_from_ja3() {
        // 0x0A0A and 0xFAFA are GREASE values
        let ciphers = &[0x0A0Au16, 0xC02B, 0xFAFA, 0xC02F];
        let buf = build_clienthello_bytes(0x0303, ciphers, &[]);

        let info = parse_clienthello(&buf).unwrap();
        let ja3 = TlsFingerprint::compute(&info);

        // GREASE values must not appear in the JA3 string
        assert!(!ja3.ja3_string.contains("2570")); // 0x0A0A = 2570
        assert!(!ja3.ja3_string.contains("64250")); // 0xFAFA = 64250
        assert!(ja3.ja3_string.contains("49195")); // 0xC02B
        assert!(ja3.ja3_string.contains("49199")); // 0xC02F
    }

    #[test]
    fn test_ja3_string_format() {
        let ciphers = &[0xC02Bu16, 0xC02F];
        let groups_data = supported_groups_ext(&[0x001Du16]);
        let formats_data = ec_point_formats_ext(&[0x00]);
        let extensions = vec![(0x000Au16, groups_data), (0x000Bu16, formats_data)];
        let buf = build_clienthello_bytes(0x0303, ciphers, &extensions);

        let info = parse_clienthello(&buf).unwrap();
        let fp = TlsFingerprint::compute(&info);

        // Format: VERSION,CIPHERS,EXTENSIONS,GROUPS,FORMATS
        let parts: Vec<&str> = fp.ja3_string.split(',').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "771"); // TLS 1.2 = 0x0303 = 771
        assert_eq!(parts[1], "49195-49199");
        assert_eq!(parts[2], "10-11"); // extension types 0x000A and 0x000B
        assert_eq!(parts[3], "29"); // 0x001D = 29
        assert_eq!(parts[4], "0");
    }

    #[test]
    fn test_ja3_hash_is_32_hex_chars() {
        let buf = build_clienthello_bytes(0x0303, &[0xC02Bu16], &[]);
        let info = parse_clienthello(&buf).unwrap();
        let fp = TlsFingerprint::compute(&info);

        assert_eq!(fp.ja3.len(), 32);
        assert!(fp.ja3.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_ja4_format() {
        let ciphers = &[0xC02Bu16, 0xC02F];
        let alpn_data = {
            let proto = b"h2";
            let mut d = vec![0u8, (proto.len() as u8 + 1), proto.len() as u8];
            d.extend_from_slice(proto);
            d
        };
        let extensions = vec![(0x0010u16, alpn_data)];
        let buf = build_clienthello_bytes(0x0303, ciphers, &extensions);

        let info = parse_clienthello(&buf).unwrap();
        let fp = TlsFingerprint::compute(&info);

        // JA4 starts with "t12_" (TLS 1.2, 2 ciphers)
        assert!(fp.ja4.starts_with("t12_"), "got: {}", fp.ja4);
        // ALPN field should be "h2"
        let parts: Vec<&str> = fp.ja4.split('_').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[3], "h2");
    }

    #[test]
    fn test_ja3_deterministic() {
        let buf = build_clienthello_bytes(0x0303, &[0xC02Bu16, 0xC02F], &[]);
        let info = parse_clienthello(&buf).unwrap();
        let fp1 = TlsFingerprint::compute(&info);
        let fp2 = TlsFingerprint::compute(&info);
        assert_eq!(fp1.ja3, fp2.ja3);
        assert_eq!(fp1.ja4, fp2.ja4);
    }

    #[test]
    fn test_parse_invalid_not_tls() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(parse_clienthello(buf).is_none());
    }

    #[test]
    fn test_parse_truncated_returns_none() {
        let buf = &[0x16u8, 0x03, 0x01, 0x00, 0x10]; // record header only, no data
        assert!(parse_clienthello(buf).is_none());
    }

    #[test]
    fn test_parse_sni_extension() {
        let sni_data = {
            let name = b"example.com";
            let name_len = name.len() as u16;
            let list_len = name_len + 3; // name_type(1) + name_len(2) + name
            let mut d = list_len.to_be_bytes().to_vec();
            d.push(0x00); // host_name type
            d.extend_from_slice(&name_len.to_be_bytes());
            d.extend_from_slice(name);
            d
        };
        let extensions = vec![(0x0000u16, sni_data)];
        let buf = build_clienthello_bytes(0x0303, &[0xC02Bu16], &extensions);

        let info = parse_clienthello(&buf).unwrap();
        assert_eq!(info.sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_alpn_extension() {
        let alpn_data = {
            let proto = b"http/1.1";
            let mut d = vec![0u8, (proto.len() as u8 + 1), proto.len() as u8];
            d.extend_from_slice(proto);
            d
        };
        let extensions = vec![(0x0010u16, alpn_data)];
        let buf = build_clienthello_bytes(0x0303, &[0xC02Bu16], &extensions);

        let info = parse_clienthello(&buf).unwrap();
        assert_eq!(info.alpn_first, Some("http/1.1".to_string()));
    }
}
