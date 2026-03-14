//! Token management web routes.
//!
//! Authenticated pages for creating, listing, and revoking API tokens.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;

use crate::auth::device_code::generate_api_token;
use crate::auth::session::{MaybeUser, SessionUser};
use crate::db::TokenRecord;
use crate::error::RegistryError;
use crate::AppState;

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "settings_tokens.html")]
struct TokensTemplate {
    search_query: String,
    user: Option<SessionUser>,
    tokens: Vec<TokenRecord>,
}

#[derive(Template)]
#[template(path = "token_created.html")]
struct TokenCreatedTemplate {
    search_query: String,
    user: Option<SessionUser>,
    token_name: String,
    raw_token: String,
}

fn render(tmpl: &impl Template) -> Result<Response, RegistryError> {
    let html = tmpl
        .render()
        .map_err(|e| RegistryError::Internal(format!("Template render error: {e}")))?;
    Ok(Html(html).into_response())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /settings/tokens — list user's API tokens.
pub async fn tokens_page(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
) -> Result<Response, RegistryError> {
    let Some(session_user) = user.clone() else {
        return Ok(Redirect::to("/login?next=/settings/tokens").into_response());
    };

    let tokens = state.db.list_tokens(session_user.id)?;

    render(&TokensTemplate {
        search_query: String::new(),
        user,
        tokens,
    })
}

/// Token creation form.
#[derive(serde::Deserialize)]
pub struct CreateTokenForm {
    token_name: String,
}

/// POST /settings/tokens — create a new API token.
pub async fn create_token(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
    Form(form): Form<CreateTokenForm>,
) -> Result<Response, RegistryError> {
    let Some(session_user) = user.clone() else {
        return Ok(Redirect::to("/login").into_response());
    };

    let token_name = if form.token_name.trim().is_empty() {
        "default".to_string()
    } else {
        form.token_name.trim().to_string()
    };

    let raw_token = generate_api_token();
    state
        .db
        .create_token(session_user.id, &token_name, &raw_token)?;

    render(&TokenCreatedTemplate {
        search_query: String::new(),
        user,
        token_name,
        raw_token,
    })
}

/// Token revoke form.
#[derive(serde::Deserialize)]
pub struct RevokeTokenForm {
    token_id: i64,
}

/// POST /settings/tokens/revoke — revoke an API token.
pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
    Form(form): Form<RevokeTokenForm>,
) -> Result<Response, RegistryError> {
    let Some(session_user) = user else {
        return Ok(Redirect::to("/login").into_response());
    };

    state.db.revoke_token(form.token_id, session_user.id)?;

    Ok(Redirect::to("/settings/tokens").into_response())
}
