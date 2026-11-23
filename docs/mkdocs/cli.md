# Command Line Usage

`wj-burnerca` takes one or more positional domains and three optional
flags. The output directory defaults to `./<domain>/`, named after the
first domain.

## Synopsis

```bash
wj-burnerca <domain> [<domain> ...] [--days N] [--out DIR] [--force]
```

## Examples

```bash
# Default: 7-day validity, output to ./example.com/
wj-burnerca example.com

# Several domains: one CA constrained to all of them, one cert covering
# each domain and its wildcard, output to ./example.com/
wj-burnerca example.com example.net api.example.com

# Longer validity (CA and cert expire together)
wj-burnerca example.com --days 30

# Custom output dir
wj-burnerca example.com --out ./dev/ca/

# Overwrite an existing non-empty output dir
wj-burnerca example.com --out ./dev/ca/ --force
```

Domains are lowercased and repeats are dropped. Keep them together on the
command line: `wj-burnerca a.test b.test --days 30` works, but
`wj-burnerca a.test --days 30 b.test` is a usage error.

## Flags

| Flag         | Required | Default             | Description                                                                                                                                                                    |
|--------------|----------|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `domain …`   | Yes      | —                   | One or more bare domains (e.g. `example.com`). The CA is name-constrained to them; the cert covers `<domain>` and `*.<domain>` for each. The first one names the output files. |
| `--days N`   | No       | `7`                 | Validity for both the CA and the cert (they expire together). Range 1–365.                                                                                                     |
| `--out DIR`  | No       | `./<first domain>/` | Output directory.                                                                                                                                                              |
| `--force`    | No       | off                 | Overwrite an existing non-empty `--out` directory.                                                                                                                             |
| `--license`  | —        | —                   | Show licence and exit.                                                                                                                                                         |
| `--version`  | —        | —                   | Show version and exit.                                                                                                                                                         |
| `-h, --help` | —        | —                   | Show help and exit.                                                                                                                                                            |

## Exit codes

- `0` — success.
- `1` — argument or validation error.
- `2` — openssl subprocess failure during generation.
- `3` — chain verification failed; tempdir shredded; `--out` untouched.
- `4` — `--out` directory exists and is non-empty without `--force`.
- `5` — could not destroy CA private key. Path is printed loudly.

## Generated `--help`

The full `--help` output, regenerated at docs build time:

```
--8<-- "_generated_command_line_help.txt"
```
