use std::net::{IpAddr, Ipv4Addr};

// Returns true if an IPv4 address points somewhere a server-side
// request should NEVER go (internal networks, the machine itself, etc.)
fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets(); // the 4 numbers of the IP, e.g. [10, 0, 0, 5]
    ip.is_private()           // home/office networks: 10.x, 172.16-31.x, 192.168.x
        || ip.is_loopback()   // the machine itself: 127.x.x.x
        || ip.is_link_local() // 169.254.x.x, where cloud metadata lives
        || ip.is_unspecified()// 0.0.0.0
        || ip.is_broadcast()  // 255.255.255.255
        || o[0] == 0          // "this network" range: 0.x.x.x
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // carrier-grade NAT: 100.64.0.0/10
}

// Main function: true = block this address, false = safe to connect.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        // IPv4: use the checks above
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // Attackers can hide an IPv4 address inside IPv6
            // (e.g. ::ffff:127.0.0.1). Unwrap it and run the IPv4 checks.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_v4(v4);
            }
            let first = v6.segments()[0]; // first 16 bits of the address
            v6.is_loopback()                      // ::1
                || v6.is_unspecified()            // ::
                || (first & 0xfe00) == 0xfc00     // private range fc00::/7
                || (first & 0xffc0) == 0xfe80     // link-local fe80::/10
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: turn a string into an IP and check it
    fn blocked(s: &str) -> bool {
        is_blocked(s.parse().unwrap())
    }

    // Internal IPv4 addresses must all be blocked
    #[test]
    fn blocks_internal_ranges() {
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                   "169.254.169.254", "100.64.0.1", "0.0.0.0"] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
    }

    // Internal IPv6 addresses, including IPv4 hidden inside IPv6
    #[test]
    fn blocks_ipv6_internal_and_mapped() {
        for ip in ["::1", "fd00::1", "fe80::1",
                   "::ffff:127.0.0.1", "::ffff:169.254.169.254"] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
    }

    // Normal public addresses must still work
    #[test]
    fn allows_public() {
        assert!(!blocked("8.8.8.8"));
        assert!(!blocked("2606:4700:4700::1111"));
    }

    // Tricky formats (decimal/hex) fail to parse, so we reject them
    #[test]
    fn rust_rejects_obfuscated_ip_forms() {
        assert!("2130706433".parse::<IpAddr>().is_err());   // = 127.0.0.1 in decimal
        assert!("0x7f.0.0.1".parse::<IpAddr>().is_err());   // hex form
    }
}