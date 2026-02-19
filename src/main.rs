use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use keyring::Entry;
use keyring::Error as KeyringError;
use reqwest::StatusCode;
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

    #[command(subcommand)]
    Config(ConfigCommands),

    Capture {
        #[arg(value_enum)]
        kind: CaptureType,

        #[arg(long, value_name = "title")]
        title: Option<String>,

        #[arg(long, value_name = "tags_csv", value_delimiter = ',')]
        tags: Option<Vec<String>>,

        #[arg(long, value_name = "url")]
        url: Option<String>,

        #[arg(long, value_name = "language")]
        language: Option<String>,

        #[arg(long, value_name = "format")]
        format: Option<String>,

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
    Status,
    Whoami,
}

#[derive(Subcommand, Debug)]
enum ConfigCommands {
    Show,
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
struct CaptureRequest {
    r#type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
}

#[derive(Debug, Serialize)]
struct SearchQuery {
    types: String,
    query: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    token: Option<String>,
}

struct ApiClient {
    base_url: String,
    client: Client,
}

struct ApiResponse {
    status: StatusCode,
    body: String,
}

enum OutputKind {
    Whoami,
    Capture(CaptureType),
    Search,
}

#[derive(Serialize)]
struct AuthStatusOutput {
    authenticated: bool,
    token_source: String,
    keyring_error: Option<String>,
}

#[derive(Serialize)]
struct ConfigShowOutput {
    api_url: String,
    token_source: String,
    keyring_error: Option<String>,
}

enum TokenSource {
    Keyring,
    Env,
    Config,
    None,
}

struct TokenStatus {
    source: TokenSource,
    keyring_error: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Auth(command) => handle_auth(command, &cli.api_url, cli.json),
        Commands::Config(command) => handle_config(command, &cli.api_url, cli.json),
        Commands::Capture {
            kind,
            title,
            tags,
            url,
            language,
            format,
            content,
        } => {
            let token = load_token()?;
            let request =
                build_capture_request(kind.clone(), title, tags, url, language, format, content)?;
            capture(&cli.api_url, token, kind, request, cli.json)
        }
        Commands::Search { types, query } => {
            let token = load_token()?;
            search(&cli.api_url, token, SearchQuery { types, query }, cli.json)
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
        AuthCommands::Status => auth_status(json),
        AuthCommands::Whoami => {
            let token = load_token()?;
            auth_whoami(api_url, token, json)
        }
    }
}

fn handle_config(command: ConfigCommands, api_url: &str, json: bool) -> Result<()> {
    match command {
        ConfigCommands::Show => config_show(api_url, json),
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
    let client = ApiClient::new(api_url);
    let response = client.whoami(&token)?;
    print_response(response, json, OutputKind::Whoami)
}

fn capture(
    api_url: &str,
    token: String,
    kind: CaptureType,
    request: CaptureRequest,
    json: bool,
) -> Result<()> {
    let client = ApiClient::new(api_url);
    let response = client.capture(&token, &request)?;
    print_response(response, json, OutputKind::Capture(kind))
}

fn search(api_url: &str, token: String, query: SearchQuery, json: bool) -> Result<()> {
    let client = ApiClient::new(api_url);
    let response = client.search(&token, &query)?;
    print_response(response, json, OutputKind::Search)
}

fn build_capture_request(
    kind: CaptureType,
    title: Option<String>,
    tags: Option<Vec<String>>,
    url: Option<String>,
    language: Option<String>,
    format: Option<String>,
    content: Option<String>,
) -> Result<CaptureRequest> {
    let tags = normalize_tags(tags);

    match kind {
        CaptureType::Note => {
            if url.is_some() {
                return Err(anyhow!("Notes do not accept --url."));
            }
            if language.is_some() {
                return Err(anyhow!("Notes do not accept --language."));
            }
            if format.is_some() {
                return Err(anyhow!("Notes do not accept --format."));
            }

            Ok(CaptureRequest {
                r#type: kind.as_str().to_string(),
                content: Some(resolve_content(content)?),
                title,
                tags,
                url: None,
                language: None,
                format: None,
            })
        }
        CaptureType::Bookmark => {
            if content.is_some() {
                return Err(anyhow!("Bookmarks do not accept CONTENT. Use --url."));
            }
            if language.is_some() {
                return Err(anyhow!("Bookmarks do not accept --language."));
            }
            if format.is_some() {
                return Err(anyhow!("Bookmarks do not accept --format."));
            }

            let url = url.ok_or_else(|| anyhow!("Bookmarks require --url."))?;

            Ok(CaptureRequest {
                r#type: kind.as_str().to_string(),
                content: None,
                title,
                tags,
                url: Some(url),
                language: None,
                format: None,
            })
        }
        CaptureType::Snippet => {
            if url.is_some() {
                return Err(anyhow!("Snippets do not accept --url."));
            }
            if format.is_some() {
                return Err(anyhow!("Snippets do not accept --format."));
            }

            Ok(CaptureRequest {
                r#type: kind.as_str().to_string(),
                content: Some(resolve_content(content)?),
                title,
                tags,
                url: None,
                language,
                format: None,
            })
        }
        CaptureType::Diagram => {
            if url.is_some() {
                return Err(anyhow!("Diagrams do not accept --url."));
            }
            if language.is_some() {
                return Err(anyhow!("Diagrams do not accept --language."));
            }

            Ok(CaptureRequest {
                r#type: kind.as_str().to_string(),
                content: Some(resolve_content(content)?),
                title,
                tags,
                url: None,
                language: None,
                format: Some(format.unwrap_or_else(|| "mermaid_v2".to_string())),
            })
        }
    }
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

fn normalize_tags(tags: Option<Vec<String>>) -> Option<Vec<String>> {
    let mut tags = tags?;
    tags = tags
        .into_iter()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect();

    if tags.is_empty() { None } else { Some(tags) }
}

fn auth_headers(token: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let value = format!("Bearer {token}");
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&value)?);
    Ok(headers)
}

fn print_response(response: ApiResponse, json: bool, kind: OutputKind) -> Result<()> {
    if json {
        println!("{}", response.body);
        if response.status.is_success() {
            return Ok(());
        }
        return Err(anyhow!("Request failed with status {}", response.status));
    }

    if !response.status.is_success() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&response.body) {
            if let Some(message) = extract_error_message(&value) {
                println!(
                    "Request failed ({status}): {message}",
                    status = response.status
                );
            } else {
                println!("{}", response.body);
            }
        } else {
            println!("{}", response.body);
        }
        return Err(anyhow!("Request failed with status {}", response.status));
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&response.body) {
        let lines = match kind {
            OutputKind::Whoami => render_whoami(&value),
            OutputKind::Capture(kind) => render_capture(&value, kind),
            OutputKind::Search => render_search(&value),
        };
        if lines.is_empty() {
            println!("{}", response.body);
        } else {
            for line in lines {
                println!("{line}");
            }
        }
    } else {
        println!("{}", response.body);
    }

    Ok(())
}

fn extract_error_message(value: &serde_json::Value) -> Option<String> {
    extract_string(value, &["error", "message", "detail", "error_description"])
}

fn render_whoami(value: &serde_json::Value) -> Vec<String> {
    let user = value
        .get("user")
        .or_else(|| value.get("data"))
        .unwrap_or(value);

    let name = extract_string(user, &["name", "full_name"]);
    let email = extract_string(user, &["email"]);
    let id = extract_string(user, &["id", "user_id"]);

    let mut lines = Vec::new();
    if let (Some(name), Some(email)) = (name.clone(), email.clone()) {
        lines.push(format!("Authenticated as {name} <{email}>."));
    } else if let Some(email) = email.clone() {
        lines.push(format!("Authenticated as {email}."));
    } else if let Some(name) = name.clone() {
        lines.push(format!("Authenticated as {name}."));
    } else {
        lines.push("Authenticated.".to_string());
    }

    if let Some(id) = id {
        lines.push(format!("User ID: {id}"));
    }

    lines
}

fn render_capture(value: &serde_json::Value, kind: CaptureType) -> Vec<String> {
    let payload = value
        .get("data")
        .or_else(|| value.get("capture"))
        .unwrap_or(value);

    let id = extract_string(payload, &["id", "capture_id"]);
    let title = extract_string(payload, &["title", "name"]);
    let r#type =
        extract_string(payload, &["type", "kind"]).unwrap_or_else(|| kind.as_str().to_string());

    let mut lines = Vec::new();
    if let Some(title) = title {
        lines.push(format!(
            "Captured {type_label}: {title}.",
            type_label = r#type
        ));
    } else {
        lines.push(format!("Captured {type_label}.", type_label = r#type));
    }

    if let Some(id) = id {
        lines.push(format!("Capture ID: {id}"));
    }

    lines
}

fn render_search(value: &serde_json::Value) -> Vec<String> {
    let results = value
        .get("results")
        .or_else(|| value.get("data"))
        .or_else(|| value.as_array().map(|_| value))
        .and_then(|val| val.as_array())
        .cloned()
        .unwrap_or_default();

    let mut lines = Vec::new();
    lines.push(format!("Found {} results.", results.len()));

    for (index, item) in results.iter().take(5).enumerate() {
        let payload = item
            .get("document")
            .or_else(|| item.get("data"))
            .unwrap_or(item);
        let title = extract_string(payload, &["title", "name", "summary"]);
        let r#type = extract_string(payload, &["type", "kind"]);
        let id = extract_string(payload, &["id", "capture_id"]);

        let mut parts = Vec::new();
        if let Some(r#type) = r#type {
            parts.push(format!("[{}]", r#type));
        }
        if let Some(title) = title {
            parts.push(title);
        }
        if let Some(id) = id {
            parts.push(format!("({id})"));
        }
        if !parts.is_empty() {
            lines.push(format!("{}. {}", index + 1, parts.join(" ")));
        }
    }

    lines
}

fn extract_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(string) = value.get(*key).and_then(|val| val.as_str()) {
            if !string.trim().is_empty() {
                return Some(string.to_string());
            }
        }
    }
    None
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

fn auth_status(json: bool) -> Result<()> {
    let status = detect_token_status();

    if json {
        let output = AuthStatusOutput {
            authenticated: status.is_authenticated(),
            token_source: status.source_label(),
            keyring_error: status.keyring_error.clone(),
        };
        println!("{}", serde_json::to_string(&output)?);
        return Ok(());
    }

    if status.is_authenticated() {
        println!("Authenticated.");
    } else {
        println!("Not authenticated.");
    }
    println!("Token source: {}", status.source_label());
    if let Some(error) = status.keyring_error {
        println!("Keyring error: {error}");
    }

    Ok(())
}

fn config_show(api_url: &str, json: bool) -> Result<()> {
    let status = detect_token_status();

    if json {
        let output = ConfigShowOutput {
            api_url: api_url.to_string(),
            token_source: status.source_label(),
            keyring_error: status.keyring_error.clone(),
        };
        println!("{}", serde_json::to_string(&output)?);
        return Ok(());
    }

    println!("API URL: {api_url}");
    println!("Token source: {}", status.source_label());
    if let Some(error) = status.keyring_error {
        println!("Keyring error: {error}");
    }

    Ok(())
}

fn detect_token_status() -> TokenStatus {
    let mut keyring_error = None;

    match load_token_keyring() {
        Ok(token) => {
            if !token.trim().is_empty() {
                return TokenStatus {
                    source: TokenSource::Keyring,
                    keyring_error: None,
                };
            }
        }
        Err(err) => {
            if let Some(keyring_err) = err.downcast_ref::<KeyringError>() {
                if !matches!(keyring_err, KeyringError::NoEntry) {
                    keyring_error = Some(keyring_err.to_string());
                }
            } else {
                keyring_error = Some(err.to_string());
            }
        }
    }

    if let Ok(token) = std::env::var(TOKEN_ENV) {
        if !token.trim().is_empty() {
            return TokenStatus {
                source: TokenSource::Env,
                keyring_error,
            };
        }
    }

    if let Some(token) = load_token_config() {
        if !token.trim().is_empty() {
            return TokenStatus {
                source: TokenSource::Config,
                keyring_error,
            };
        }
    }

    TokenStatus {
        source: TokenSource::None,
        keyring_error,
    }
}

impl TokenStatus {
    fn is_authenticated(&self) -> bool {
        !matches!(self.source, TokenSource::None)
    }

    fn source_label(&self) -> String {
        match self.source {
            TokenSource::Keyring => "keyring".to_string(),
            TokenSource::Env => format!("env ({TOKEN_ENV})"),
            TokenSource::Config => "config file".to_string(),
            TokenSource::None => "none".to_string(),
        }
    }
}

impl ApiClient {
    fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }

    fn whoami(&self, token: &str) -> Result<ApiResponse> {
        let url = format!("{}/v1/auth/whoami", self.base_url);
        let response = self
            .client
            .get(url)
            .headers(auth_headers(token)?)
            .send()
            .context("Failed to call /v1/auth/whoami")?;

        to_api_response(response)
    }

    fn capture(&self, token: &str, request: &CaptureRequest) -> Result<ApiResponse> {
        let url = format!("{}/v1/capture", self.base_url);
        let mut headers = auth_headers(token)?;
        headers.insert(
            "Idempotency-Key",
            HeaderValue::from_str(&Uuid::new_v4().to_string())?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let response = self
            .client
            .post(url)
            .headers(headers)
            .json(request)
            .send()
            .context("Failed to call /v1/capture")?;

        to_api_response(response)
    }

    fn search(&self, token: &str, query: &SearchQuery) -> Result<ApiResponse> {
        let url = format!("{}/v1/search", self.base_url);
        let response = self
            .client
            .get(url)
            .headers(auth_headers(token)?)
            .query(query)
            .send()
            .context("Failed to call /v1/search")?;

        to_api_response(response)
    }
}

fn to_api_response(response: reqwest::blocking::Response) -> Result<ApiResponse> {
    let status = response.status();
    let body = response.text().context("Failed to read response body")?;
    Ok(ApiResponse { status, body })
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

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_config_dir<F>(f: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp_dir = TempDir::new().context("Failed to create temp dir")?;
        let original = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
        }

        let result = f();

        if let Some(value) = original {
            unsafe {
                std::env::set_var("XDG_CONFIG_HOME", value);
            }
        } else {
            unsafe {
                std::env::remove_var("XDG_CONFIG_HOME");
            }
        }

        result
    }

    #[test]
    fn token_config_roundtrip() -> Result<()> {
        with_temp_config_dir(|| {
            store_token_config("test-token")?;
            assert_eq!(load_token_config(), Some("test-token".to_string()));
            delete_token_config()?;
            assert!(load_token_config().is_none());
            Ok(())
        })
    }

    #[test]
    fn api_client_builds_whoami_request() -> Result<()> {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/v1/auth/whoami")
                .header("authorization", "Bearer test-token");
            then.status(200)
                .json_body(json!({"user": {"email": "hi@example.com"}}));
        });

        let client = ApiClient::new(&server.base_url());
        let response = client.whoami("test-token")?;

        mock.assert();
        assert_eq!(response.status, StatusCode::OK);
        Ok(())
    }

    #[test]
    fn api_client_builds_capture_request() -> Result<()> {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/capture")
                .header("authorization", "Bearer test-token")
                .json_body(json!({
                    "type": "snippet",
                    "content": "fn main() {}",
                    "title": "Rust snippet",
                    "tags": ["rust", "cli"],
                    "language": "rust"
                }));
            then.status(200).json_body(json!({"id": "cap_123"}));
        });

        let client = ApiClient::new(&server.base_url());
        let request = CaptureRequest {
            r#type: "snippet".to_string(),
            content: Some("fn main() {}".to_string()),
            title: Some("Rust snippet".to_string()),
            tags: Some(vec!["rust".to_string(), "cli".to_string()]),
            url: None,
            language: Some("rust".to_string()),
            format: None,
        };
        let response = client.capture("test-token", &request)?;

        mock.assert();
        assert_eq!(response.status, StatusCode::OK);
        Ok(())
    }

    #[test]
    fn api_client_builds_search_request() -> Result<()> {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/v1/search")
                .query_param("types", "note,bookmark")
                .query_param("query", "postgres");
            then.status(200).json_body(json!({"results": []}));
        });

        let client = ApiClient::new(&server.base_url());
        let response = client.search(
            "test-token",
            &SearchQuery {
                types: "note,bookmark".to_string(),
                query: "postgres".to_string(),
            },
        )?;

        mock.assert();
        assert_eq!(response.status, StatusCode::OK);
        Ok(())
    }
}
