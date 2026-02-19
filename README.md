# Turbodoc CLI

Capture notes, bookmarks, snippets, and diagrams into Turbodoc, then search them from the command line.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/turbodoc-org/turbodoc-cli/main/scripts/install.sh | bash
```

To install a specific version or change the bin directory:

```bash
VERSION=v0.1.0 BIN_DIR=$HOME/.local/bin \
  curl -fsSL https://raw.githubusercontent.com/turbodoc-org/turbodoc-cli/main/scripts/install.sh | bash
```

Or build from source:

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
turbodoc auth status
turbodoc auth whoami
turbodoc auth logout
```

If a system keyring is unavailable, set `TURBODOC_TOKEN` or pass `--insecure-store-token`.

## Capture

```bash
turbodoc capture note "Meeting notes for today" --title "Daily standup" --tags team,meeting
turbodoc capture bookmark --url https://example.com --title "Reference" --tags docs
echo "Snippet from stdin" | turbodoc capture snippet --language rust --title "Helper" --tags cli
echo "flowchart TD\nA-->B" | turbodoc capture diagram --title "Pipeline" --format mermaid_v2 --tags design
```

## Search

```bash
turbodoc search --types note,bookmark --query "postgres optimization"
```

## Configuration

- Default API URL: `https://api.turbodoc.ai`
- Override via `--api-url` or `TURBODOC_API_URL`
- Raw JSON output: pass `--json`
- Show config: `turbodoc config show`
