# Command Line Usage

`wj-burnerca` takes one positional `domain` and three optional flags. The
output directory defaults to `./<domain>/`.

## Synopsis

```bash
wj-burnerca <domain> [--days N] [--out DIR] [--force]
```

## Examples

```bash
# Default: 365-day validity, output to ./example.com/
wj-burnerca example.com

# Shorter validity (CA and cert expire together)
wj-burnerca example.com --days 30

# Custom output dir
wj-burnerca example.com --out ./dev/ca/

# Overwrite an existing non-empty output dir
wj-burnerca example.com --out ./dev/ca/ --force
```

## Flags

| Flag             | Required | Default          | Description                                                                                                                  |
|------------------|----------|------------------|------------------------------------------------------------------------------------------------------------------------------|
| `domain`         | Yes      | —                | Bare domain (e.g. `example.com`). The CA is name-constrained to this domain; the cert covers `<domain>` and `*.<domain>`.    |
| `--days N`       | No       | `365`            | Validity for both the CA and the cert (they expire together). Range 1–365.                                                   |
| `--out DIR`      | No       | `./<domain>/`    | Output directory.                                                                                                            |
| `--force`        | No       | off              | Overwrite an existing non-empty `--out` directory.                                                                           |
| `--license`      | —        | —                | Show licence and exit.                                                                                                       |
| `--version`      | —        | —                | Show version and exit.                                                                                                       |
| `-h, --help`     | —        | —                | Show help and exit.                                                                                                          |

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
