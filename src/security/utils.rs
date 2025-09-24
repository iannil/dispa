use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Network utility functions for IP matching and CIDR support
pub mod network {
    use super::*;

    pub fn ip_match(pattern: &str, ip: &IpAddr) -> bool {
        // CIDR support: a.b.c.d/len or xxxx::/len
        if let Some((addr, len)) = parse_cidr(pattern) {
            return cidr_match(&addr, len, ip);
        }
        match ip {
            IpAddr::V4(v4) => {
                let s = v4.to_string();
                if let Some(pfx) = pattern.strip_suffix(".*") {
                    s.starts_with(pfx)
                } else {
                    s == pattern
                }
            }
            IpAddr::V6(v6) => v6.to_string() == pattern,
        }
    }

    fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
        let (addr_str, len_str) = s.split_once('/')?;
        let addr: IpAddr = addr_str.parse().ok()?;
        let len: u8 = len_str.parse().ok()?;
        Some((addr, len))
    }

    fn cidr_match(net: &IpAddr, prefix: u8, ip: &IpAddr) -> bool {
        match (net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let n = u32::from(*n);
                let i = u32::from(*i);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix as u32)
                };
                (n & mask) == (i & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let n = u128::from(*n);
                let i = u128::from(*i);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix as u32)
                };
                (n & mask) == (i & mask)
            }
            _ => false,
        }
    }
}

/// Cryptographic utility functions
pub mod crypto {
    use super::*;

    pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
        const BLOCK: usize = 64;
        let mut k = if key.len() > BLOCK {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.finalize().to_vec()
        } else {
            key.to_vec()
        };
        if k.len() < BLOCK {
            k.resize(BLOCK, 0);
        }
        let mut ipad = vec![0x36u8; BLOCK];
        let mut opad = vec![0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut ih = Sha256::new();
        ih.update(&ipad);
        ih.update(msg);
        let inner = ih.finalize();
        let mut oh = Sha256::new();
        oh.update(&opad);
        oh.update(inner);
        oh.finalize().to_vec()
    }

    pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
        // Convert URL-safe to standard base64
        let mut b = s.replace('-', "+").replace('_', "/");
        while !b.len().is_multiple_of(4) {
            b.push('=');
        }
        base64_decode(&b)
    }

    pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
        // Minimal base64 decoder for standard alphabet with padding
        fn val(c: u8) -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                b'=' => Some(64), // padding
                _ => None,
            }
        }
        let bytes = s.as_bytes();
        if !bytes.len().is_multiple_of(4) {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        let mut i = 0;
        while i < bytes.len() {
            let a = val(bytes[i])?;
            let b = val(bytes[i + 1])?;
            let c = val(bytes[i + 2])?;
            let d = val(bytes[i + 3])?;
            i += 4;
            if a == 64 || b == 64 {
                return None;
            }
            let n = ((a as u32) << 18)
                | ((b as u32) << 12)
                | (if c == 64 { 0 } else { (c as u32) << 6 })
                | (if d == 64 { 0 } else { d as u32 });
            out.push(((n >> 16) & 0xFF) as u8);
            if c != 64 {
                out.push(((n >> 8) & 0xFF) as u8);
            }
            if d != 64 {
                out.push((n & 0xFF) as u8);
            }
        }
        Some(out)
    }

    // Minimal base64 encoder (used by tests/JWT helpers)
    #[cfg(test)]
    pub fn base64_encode(data: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((data.len().div_ceil(3)) * 4);
        let mut i = 0;
        while i + 3 <= data.len() {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push(TABLE[(n & 63) as usize] as char);
            i += 3;
        }
        match data.len() - i {
            1 => {
                let n = (data[i] as u32) << 16;
                out.push(TABLE[((n >> 18) & 63) as usize] as char);
                out.push(TABLE[((n >> 12) & 63) as usize] as char);
                out.push('=');
                out.push('=');
            }
            2 => {
                let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
                out.push(TABLE[((n >> 18) & 63) as usize] as char);
                out.push(TABLE[((n >> 12) & 63) as usize] as char);
                out.push(TABLE[((n >> 6) & 63) as usize] as char);
                out.push('=');
            }
            _ => {}
        }
        out
    }
}
