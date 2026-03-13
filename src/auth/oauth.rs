//! GitHub OAuth2 authorization code flow.
//!
//! Handles the token exchange and user info fetch for GitHub OAuth.
//! Used by the web auth routes when `AUTH_MODE=github_oauth`.

use serde::Deserialize;

use crate::error::RegistryError;

/// GitHub user info returned by `GET /user`.
#[derive(Debug, Deserialize)]
pub struct GitHubUser {
    /// GitHub numeric user ID (stable identifier).
    pub id: u64,
    /// GitHub login (username).
    pub login: String,
    /// Display name.
    pub name: Option<String>,
    /// Avatar URL.
    pub avatar_url: Option<String>,
    /// Email (may be null if private).
    pub email: Option<String>,
}

/// Exchanges an OAuth authorization code for an access token.
///
/// Calls `POST https://github.com/login/oauth/access_token`.
pub async fn exchange_code(
    client_id: &str,
    client_secret: &str,
    code: &str,
) -> Result<String, RegistryError> {
    let client = reqwest::Client::new();

    let resp = client
        .post("https://github.com/login/oauth/access_token")
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
        ])
        .send()
        .await
        .map_err(|e| RegistryError::Internal(format!("GitHub token exchange failed: {e}")))?;

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }

    let body: TokenResponse = resp
        .json()
        .await
        .map_err(|e| RegistryError::Internal(format!("GitHub token parse failed: {e}")))?;

    if let Some(error) = body.error {
        let desc = body.error_description.unwrap_or_default();
        return Err(RegistryError::AuthFailed(format!(
            "GitHub OAuth error: {error} — {desc}"
        )));
    }

    body.access_token
        .ok_or_else(|| RegistryError::Internal("GitHub returned no access_token".to_string()))
}

/// Fetches the authenticated user's profile from GitHub.
///
/// Calls `GET https://api.github.com/user` with the access token.
pub async fn fetch_user(access_token: &str) -> Result<GitHubUser, RegistryError> {
    let client = reqwest::Client::new();

    let resp = client
        .get("https://api.github.com/user")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {access_token}"),
        )
        .header(reqwest::header::USER_AGENT, "duumbi-registry")
        .send()
        .await
        .map_err(|e| RegistryError::Internal(format!("GitHub user fetch failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(RegistryError::AuthFailed(format!(
            "GitHub API returned {status}: {body}"
        )));
    }

    resp.json()
        .await
        .map_err(|e| RegistryError::Internal(format!("GitHub user parse failed: {e}")))
}

/// Builds the GitHub authorization URL for the initial redirect.
#[must_use]
pub fn authorize_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    format!(
        "https://github.com/login/oauth/authorize?client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &scope=read:user,user:email\
         &state={state}"
    )
}
