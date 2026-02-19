use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use keyring::Entry;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const DEFAULT_API_URL: &str = "https://api.turbodoc.ai";
const CONFIG_DIR_NAME: &str = "turbodoc";
const CONFIG_FILE_NAME: &str = "config.toml";
const TOKEN_ENV: &str = "TURBODOC_TOKEN";

#[derive(Parser, Debug)]
#[command(name = "turbodoc", version, about = "Turbodoc CLI")]
struct Cli {
    #[arg(long, env = "TURBODOC_API_URL", default_value = DEFAULT_API_URL)]
    api_url: String,

    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(subcommand)]
    Auth(AuthCommands),

    Capture {
        #[arg(value_enum)]
        kind: CaptureType,

        #[arg(value_name = "CONTENT")]
        content: Option<String>,
    },

    Search {
        #[arg(long, value_name = "types_csv")]
        types: String,

        #[arg(long, value_name = "query_text")]
        query: String,
    },
}

#[derive(Subcommand, Debug)]
enum AuthCommands {
    Login {
        #[arg(long, value_name = "TOKEN")]
        pat: String,

        #[arg(long)]
        insecure_store_token: bool,
    },
    Logout,
    Whoami,
}

#[derive(ValueEnum, Clone, Debug)]
enum CaptureType {
    Note,
    Bookmark,
    Snippet,
    Diagram,
}

impl CaptureType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Bookmark => "bookmark",
            Self::Snippet => "snippet",
            Self::Diagram => "diagram",
        }
    }
}

#[derive(Debug, Serialize)]
struct CaptureRequest<'a> {
    r#type: &'a str,
    content: &'a str,
}

#[derive(Debug, Serialize)]
struct SearchQuery<'a> {
    types: &'a str,
    query: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    token: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Auth(command) => handle_auth(command, &cli.api_url, cli.json),
        Commands::Capture { kind, content } => {
            let token = load_token()?;
            let content = resolve_content(content)?;
            capture(&cli.api_url, token, kind, content, cli.json)
        }
        Commands::Search { types, query } => {
            let token = load_token()?;
            search(&cli.api_url, token, types, query, cli.json)
        }
    }
}

fn handle_auth(command: AuthCommands, api_url: &str, json: bool) -> Result<()> {
    match command {
        AuthCommands::Login {
            pat,
            insecure_store_token,
        } => auth_login(&pat, insecure_store_token),
        AuthCommands::Logout => auth_logout(),
        AuthCommands::Whoami => {
            let token = load_token()?;
            auth_whoami(api_url, token, json)
        }
    }
}

fn auth_login(pat: &str, insecure_store_token: bool) -> Result<()> {
    match store_token_keyring(pat) {
        Ok(()) => {
            println!("Token stored in system keyring.");
            Ok(())
        }
        Err(err) => {
            if insecure_store_token {
                store_token_config(pat)?;
                println!("Keyring unavailable ({err}); token stored in config file.");
                Ok(())
            } else if std::env::var(TOKEN_ENV).is_ok() {
                println!("Keyring unavailable ({err}); using {TOKEN_ENV} environment variable.");
                Ok(())
            } else {
                Err(anyhow!(
                    "Keyring unavailable ({err}). Set {TOKEN_ENV} or pass --insecure-store-token."
                ))
            }
        }
    }
}

fn auth_logout() -> Result<()> {
    let mut removed = false;

    if delete_token_keyring().is_ok() {
        removed = true;
        println!("Removed token from system keyring.");
    }

    if delete_token_config().is_ok() {
        removed = true;
        println!("Removed token from config file.");
    }

    if !removed {
        println!("No stored token found. If set, clear {TOKEN_ENV} manually.");
    } else {
        println!("If set, clear {TOKEN_ENV} manually.");
    }

    Ok(())
}

fn auth_whoami(api_url: &str, token: String, json: bool) -> Result<()> {
    let client = Client::new();
    let url = format!("{api_url}/v1/auth/whoami");
    let response = client
        .get(url)
        .headers(auth_headers(&token)?)
        .send()
        .context("Failed to call /v1/auth/whoami")?;

    print_response(response, json)
}

fn capture(
    api_url: &str,
    token: String,
    kind: CaptureType,
    content: String,
    json: bool,
) -> Result<()> {
    let client = Client::new();
    let url = format!("{api_url}/v1/capture");
    let mut headers = auth_headers(&token)?;
    headers.insert(
        "Idempotency-Key",
        HeaderValue::from_str(&Uuid::new_v4().to_string())?,
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let body = CaptureRequest {
        r#type: kind.as_str(),
        content: &content,
    };

    let response = client
        .post(url)
        .headers(headers)
        .json(&body)
        .send()
        .context("Failed to call /v1/capture")?;

    print_response(response, json)
}

fn search(api_url: &str, token: String, types: String, query: String, json: bool) -> Result<()> {
    let client = Client::new();
    let url = format!("{api_url}/v1/search");
    let response = client
        .get(url)
        .headers(auth_headers(&token)?)
        .query(&SearchQuery {
            types: &types,
            query: &query,
        })
        .send()
        .context("Failed to call /v1/search")?;

    print_response(response, json)
}

fn resolve_content(content: Option<String>) -> Result<String> {
    if let Some(content) = content {
        return Ok(content);
    }

    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("Failed to read stdin")?;

    let trimmed = buffer.trim_matches(['\n', '\r']).to_string();
    if trimmed.is_empty() {
        Err(anyhow!(
            "No content provided. Pass CONTENT or pipe content via stdin."
        ))
    } else {
        Ok(trimmed)
    }
}

fn auth_headers(token: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let value = format!("Bearer {token}");
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&value)?);
    Ok(headers)
}

fn print_response(response: reqwest::blocking::Response, json: bool) -> Result<()> {
    let status = response.status();
    let text = response.text().context("Failed to read response body")?;

    if json {
        println!("{text}");
    } else if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("{text}");
    }

    if status.is_success() {
        Ok(())
    } else {
        Err(anyhow!("Request failed with status {status}"))
    }
}

fn load_token() -> Result<String> {
    if let Ok(token) = load_token_keyring() {
        return Ok(token);
    }

    if let Ok(token) = std::env::var(TOKEN_ENV) {
        if !token.trim().is_empty() {
            return Ok(token);
        }
    }

    if let Some(token) = load_token_config() {
        return Ok(token);
    }

    Err(anyhow!(
        "No token found. Run `turbodoc auth login --pat TOKEN` or set {TOKEN_ENV}."
    ))
}

fn keyring_entry() -> Result<Entry> {
    Ok(Entry::new("turbodoc", "default")?)
}

fn store_token_keyring(token: &str) -> Result<()> {
    let entry = keyring_entry()?;
    entry.set_password(token)?;
    Ok(())
}

fn load_token_keyring() -> Result<String> {
    let entry = keyring_entry()?;
    Ok(entry.get_password()?)
}

fn delete_token_keyring() -> Result<()> {
    let entry = keyring_entry()?;
    entry.delete_password()?;
    Ok(())
}

fn config_path() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("No config directory available"))?;
    Ok(base.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME))
}

fn ensure_config_dir(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).context("Failed to create config directory")?;
    }
    Ok(())
}

fn store_token_config(token: &str) -> Result<()> {
    let path = config_path()?;
    ensure_config_dir(&path)?;

    let config = Config {
        token: Some(token.to_string()),
    };
    let contents = toml::to_string(&config).context("Failed to serialize config")?;
    fs::write(&path, contents).context("Failed to write config file")?;
    Ok(())
}

fn load_token_config() -> Option<String> {
    let path = config_path().ok()?;
    let contents = fs::read_to_string(path).ok()?;
    let config: Config = toml::from_str(&contents).ok()?;
    config.token
}

fn delete_token_config() -> Result<()> {
    let path = config_path()?;
    if path.exists() {
        fs::remove_file(path).context("Failed to remove config file")?;
    }
    Ok(())
}
