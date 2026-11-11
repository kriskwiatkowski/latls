# latls

TLS 1.3 client with `no_std` and no allocator support.

## Bare-metal entropy

`no_std` builds use `getrandom`'s custom backend for ephemeral P-256 keys.
Applications targeting bare metal must register a platform entropy source with
`getrandom::register_custom_getrandom!` before establishing a TLS connection.

## License

Apache-2.0
