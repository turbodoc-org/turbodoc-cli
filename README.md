# Turbodoc CLI

Capture notes, bookmarks, snippets, and diagrams into Turbodoc, then search them from the command line.

## Install

```bash
cargo build
```

The binaries are `turbodoc` and `td`.

```bash
./target/debug/turbodoc --help
./target/debug/td --help
```

## Auth

```bash
turbodoc auth login --pat YOUR_TOKEN
turbodoc auth whoami
turbodoc auth logout
```

If a system keyring is unavailable, set `TURBODOC_TOKEN` or pass `--insecure-store-token`.

## Capture

```bash
turbodoc capture note "Meeting notes for today"
echo "Snippet from stdin" | turbodoc capture snippet
```

## Search

```bash
turbodoc search --types note,bookmark --query "postgres optimization"
```

## Configuration

- Default API URL: `https://api.turbodoc.ai`
- Override via `--api-url` or `TURBODOC_API_URL`
- Raw JSON output: pass `--json`
