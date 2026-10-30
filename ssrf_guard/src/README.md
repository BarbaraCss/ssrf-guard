# ssrf_guard

A small Rust library that decides whether an IP address is safe for a server to connect to. It is a learning project that defends against one part of **SSRF** (Server-Side Request Forgery).

## Why

SSRF happens when an attacker tricks a server into making requests to places it shouldn't reach, such as internal networks or the cloud metadata address (`169.254.169.254`). I built this after completing the *Server-side vulnerabilities* path on PortSwigger Web Security Academy. It is also related to my team project (Mü), which fetches links that users share.

## What it does

`is_blocked(ip)` returns `true` for addresses that should never be contacted:

- Loopback: `127.0.0.1`, `::1`
- Private networks: `10.x`, `172.16.x`, `192.168.x`
- Link-local, where cloud metadata lives: `169.254.x.x`
- Carrier-grade NAT: `100.64.x.x`
- IPv4 hidden inside IPv6, such as `::ffff:127.0.0.1`

Disguised forms like decimal (`2130706433`) or hex (`0x7f.0.0.1`) fail to parse in Rust, so they are rejected.

## How to run

```bash
cargo test
```

All 4 tests pass.

## What I did and what AI did

An AI assistant drafted a larger safe-fetch design and the first version of this code. I scoped the project down to the IP-validation core, ran and verified the tests myself, and added comments so I understand each line.

## Limitations

This is **one layer, not a full SSRF defense**. It does not yet handle:

- DNS rebinding (a domain that resolves to a safe IP first, then an internal one)
- Redirects to internal addresses
- Response size and time limits
- Rarer ranges such as NAT64 and 6to4

## Next steps

Add DNS resolution checks, connection pinning, redirect re-checking, and tests for each.

## Resources

- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)