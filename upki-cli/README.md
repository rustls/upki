# upki-cli

The `upki` command-line tool: browser-grade certificate revocation checking for
monitoring, testing and alerting.

It uses [upki](https://github.com/rustls/upki)'s
[crlite-clubcard](https://eprint.iacr.org/2025/610) revocation data, which
updates several times per day. The CLI both synchronizes that data and checks
certificates against it.

## Usage

```
Platform-independent browser-grade certificate infrastructure

Usage: upki [OPTIONS] <COMMAND>

Commands:
  fetch             Update the local cache of crlite filters, downloading them as needed
  verify            Verifies the local cache of crlite filters
  revocation        Checks the revocation status of a certificate
  show-config-path  Print the location of the configuration file
  show-config       Print the configuration that will be used
  help              Print this message or the help of the given subcommand(s)

Options:
      --config-file <CONFIG_FILE>  Use this specific configuration file.  This must exist
      --verbose                    Emit logging output
  -h, --help                       Print help (see more with '--help')
  -V, --version                    Print version
```

## License

This crate is distributed under the terms of both the Apache License (Version
2.0) and the MIT license, at your option. See [LICENSE-APACHE] and [LICENSE-MIT]
in the repository root for details.

[LICENSE-APACHE]: https://github.com/rustls/upki/blob/main/LICENSE-APACHE
[LICENSE-MIT]: https://github.com/rustls/upki/blob/main/LICENSE-MIT
