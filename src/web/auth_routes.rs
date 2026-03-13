//! Web authentication routes.
//!
//! Handles login, logout, GitHub OAuth callback, registration (local mode),
//! and device code verification.

use std::sync::Arc;

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::AppState;
use crate::AuthMode;
use crate::auth::device_code::{generate_api_token, generate_csrf_state};
use crate::auth::session::{self, MaybeUser, SessionUser};
use crate::auth::{jwt, oauth};
use crate::error::RegistryError;

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    search_query: String,
    user: Option<SessionUser>,
    auth_mode: String,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    search_query: String,
    user: Option<SessionUser>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "device.html")]
struct DeviceTemplate {
    search_query: String,
    user: Option<SessionUser>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "device_success.html")]
struct DeviceSuccessTemplate {
    search_query: String,
    user: Option<SessionUser>,
}

fn render(tmpl: &impl Template) -> Result<Response, RegistryError> {
    let html = tmpl
        .render()
        .map_err(|e| RegistryError::Internal(format!("Template render error: {e}")))?;
    Ok(Html(html).into_response())
}

// ---------------------------------------------------------------------------
// Login / Logout
// ---------------------------------------------------------------------------

/// GET /login — shows login page (GitHub button or password form).
pub async fn login_page(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
) -> Result<Response, RegistryError> {
    if user.is_some() {
        return Ok(Redirect::to("/").into_response());
    }

    render(&LoginTemplate {
        search_query: String::new(),
        user: None,
        auth_mode: state.auth_mode.as_str().to_string(),
        error: None,
    })
}

/// POST /logout — clears session cookie.
pub async fn logout() -> Response {
    let cookie = session::build_logout_cookie();
    (
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::SET_COOKIE, cookie),
            (axum::http::header::LOCATION, "/".to_string()),
        ],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GitHub OAuth (#199)
// ---------------------------------------------------------------------------

/// GET /auth/github — redirects to GitHub authorize URL.
pub async fn github_redirect(
    State(state): State<Arc<AppState>>,
) -> Result<Response, RegistryError> {
    let client_id = state
        .github_client_id
        .as_deref()
        .ok_or_else(|| RegistryError::Internal("GITHUB_CLIENT_ID not configured".to_string()))?;

    let csrf_state = generate_csrf_state();
    let redirect_uri = format!("{}/auth/github/callback", state.base_url);
    let url = oauth::authorize_url(client_id, &redirect_uri, &csrf_state);

    // Store CSRF state in cookie
    let csrf_cookie =
        format!("oauth_state={csrf_state}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=600");

    Ok((
        StatusCode::FOUND,
        [
            (axum::http::header::LOCATION, url),
            (axum::http::header::SET_COOKIE, csrf_cookie),
        ],
    )
        .into_response())
}

/// OAuth callback query parameters.
#[derive(serde::Deserialize)]
pub struct OAuthCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// GET /auth/github/callback — processes the OAuth callback.
pub async fn github_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<OAuthCallback>,
    req: axum::extract::Request,
) -> Result<Response, RegistryError> {
    // Check for OAuth error
    if let Some(error) = params.error {
        return render(&LoginTemplate {
            search_query: String::new(),
            user: None,
            auth_mode: state.auth_mode.as_str().to_string(),
            error: Some(format!("GitHub login failed: {error}")),
        });
    }

    let code = params
        .code
        .ok_or_else(|| RegistryError::AuthFailed("Missing authorization code".to_string()))?;

    // Verify CSRF state
    let cookie_header = req
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let stored_state = cookie_header
        .split(';')
        .filter_map(|s| s.trim().strip_prefix("oauth_state="))
        .next();

    if let (Some(stored), Some(received)) = (stored_state, params.state.as_deref()) {
        if stored != received {
            return Err(RegistryError::AuthFailed("CSRF state mismatch".to_string()));
        }
    }

    // Exchange code for access token
    let client_id = state
        .github_client_id
        .as_deref()
        .ok_or_else(|| RegistryError::Internal("GITHUB_CLIENT_ID not configured".to_string()))?;
    let client_secret = state.github_client_secret.as_deref().ok_or_else(|| {
        RegistryError::Internal("GITHUB_CLIENT_SECRET not configured".to_string())
    })?;

    let access_token = oauth::exchange_code(client_id, client_secret, &code).await?;

    // Fetch GitHub user info
    let gh_user = oauth::fetch_user(&access_token).await?;

    // Find or create user in our database
    let user = state.db.find_or_create_oauth_user(
        "github",
        &gh_user.id.to_string(),
        &gh_user.login,
        gh_user.avatar_url.as_deref(),
        gh_user.email.as_deref(),
        Some(&access_token),
    )?;

    // Create JWT session
    let jwt_token = jwt::create_token(
        &state.jwt_secret,
        user.id,
        &user.username,
        user.avatar_url.as_deref(),
        jwt::SESSION_MAX_AGE_SECS,
    )
    .map_err(|e| RegistryError::Internal(format!("JWT creation failed: {e}")))?;

    let session_cookie = session::build_session_cookie(&jwt_token, &state.base_url);

    // Build response with session cookie and clear CSRF cookie
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::LOCATION,
        "/".parse().expect("invariant: valid header"),
    );
    headers.insert(
        axum::http::header::SET_COOKIE,
        session_cookie.parse().expect("invariant: valid cookie"),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        "oauth_state=; HttpOnly; SameSite=Lax; Path=/auth; Max-Age=0"
            .parse()
            .expect("invariant: valid cookie"),
    );

    Ok((StatusCode::FOUND, headers).into_response())
}

// ---------------------------------------------------------------------------
// Local password auth (#203)
// ---------------------------------------------------------------------------

/// GET /register — registration form (local_password mode only).
pub async fn register_page(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
) -> Result<Response, RegistryError> {
    if !matches!(state.auth_mode, AuthMode::LocalPassword) {
        return Ok(Redirect::to("/login").into_response());
    }

    if user.is_some() {
        return Ok(Redirect::to("/").into_response());
    }

    render(&RegisterTemplate {
        search_query: String::new(),
        user: None,
        error: None,
    })
}

/// Registration form data.
#[derive(serde::Deserialize)]
pub struct RegisterForm {
    username: String,
    password: String,
    password_confirm: String,
}

/// POST /register — creates a new user with password.
pub async fn register_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RegisterForm>,
) -> Result<Response, RegistryError> {
    if !matches!(state.auth_mode, AuthMode::LocalPassword) {
        return Err(RegistryError::AuthFailed(
            "Registration not available in this auth mode".to_string(),
        ));
    }

    // Validate
    if form.username.trim().is_empty() {
        return render(&RegisterTemplate {
            search_query: String::new(),
            user: None,
            error: Some("Username is required".to_string()),
        });
    }

    if form.password.len() < 8 {
        return render(&RegisterTemplate {
            search_query: String::new(),
            user: None,
            error: Some("Password must be at least 8 characters".to_string()),
        });
    }

    if form.password != form.password_confirm {
        return render(&RegisterTemplate {
            search_query: String::new(),
            user: None,
            error: Some("Passwords do not match".to_string()),
        });
    }

    // Check if username taken
    if state.db.get_user_by_username(&form.username).is_ok() {
        return render(&RegisterTemplate {
            search_query: String::new(),
            user: None,
            error: Some("Username already taken".to_string()),
        });
    }

    // Hash password and create user
    let password_hash = crate::auth::password::hash_password(&form.password)?;

    state.db.create_user(&crate::db::CreateUser {
        username: &form.username,
        display_name: None,
        avatar_url: None,
        email: None,
        password_hash: Some(&password_hash),
    })?;

    // Redirect to login
    Ok(Redirect::to("/login").into_response())
}

/// Login form data.
#[derive(serde::Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

/// POST /login — password-based login (local_password mode).
pub async fn login_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Result<Response, RegistryError> {
    if !matches!(state.auth_mode, AuthMode::LocalPassword) {
        return Err(RegistryError::AuthFailed(
            "Password login not available".to_string(),
        ));
    }

    let user = match state.db.get_user_by_username(&form.username) {
        Ok(u) => u,
        Err(_) => {
            return render(&LoginTemplate {
                search_query: String::new(),
                user: None,
                auth_mode: state.auth_mode.as_str().to_string(),
                error: Some("Invalid username or password".to_string()),
            });
        }
    };

    let hash = user
        .password_hash
        .as_deref()
        .ok_or_else(|| RegistryError::AuthFailed("This account uses OAuth login".to_string()))?;

    let valid = crate::auth::password::verify_password(&form.password, hash)?;
    if !valid {
        return render(&LoginTemplate {
            search_query: String::new(),
            user: None,
            auth_mode: state.auth_mode.as_str().to_string(),
            error: Some("Invalid username or password".to_string()),
        });
    }

    // Create JWT session
    let jwt_token = jwt::create_token(
        &state.jwt_secret,
        user.id,
        &user.username,
        user.avatar_url.as_deref(),
        jwt::SESSION_MAX_AGE_SECS,
    )
    .map_err(|e| RegistryError::Internal(format!("JWT creation failed: {e}")))?;

    let session_cookie = session::build_session_cookie(&jwt_token, &state.base_url);

    Ok((
        StatusCode::FOUND,
        [
            (axum::http::header::LOCATION, "/".to_string()),
            (axum::http::header::SET_COOKIE, session_cookie),
        ],
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Device code verification (#202)
// ---------------------------------------------------------------------------

/// GET /device — shows the device code entry form.
pub async fn device_page(
    State(_state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
) -> Result<Response, RegistryError> {
    // Must be logged in
    if user.is_none() {
        return Ok(Redirect::to("/login?next=/device").into_response());
    }

    render(&DeviceTemplate {
        search_query: String::new(),
        user,
        error: None,
    })
}

/// Device code form data.
#[derive(serde::Deserialize)]
pub struct DeviceForm {
    user_code: String,
}

/// POST /device — verifies the user code and authorizes the device.
pub async fn device_authorize(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
    Form(form): Form<DeviceForm>,
) -> Result<Response, RegistryError> {
    let Some(session_user) = user.clone() else {
        return Ok(Redirect::to("/login?next=/device").into_response());
    };

    let user_code = form.user_code.trim().to_uppercase();

    if user_code.is_empty() {
        return render(&DeviceTemplate {
            search_query: String::new(),
            user,
            error: Some("Please enter the code shown in your terminal".to_string()),
        });
    }

    // Generate a token for the CLI
    let raw_token = generate_api_token();

    let authorized =
        state
            .db
            .authorize_device_code(&user_code, session_user.id, &raw_token, "cli-login")?;

    if !authorized {
        return render(&DeviceTemplate {
            search_query: String::new(),
            user,
            error: Some("Invalid or expired code. Please try again.".to_string()),
        });
    }

    render(&DeviceSuccessTemplate {
        search_query: String::new(),
        user,
    })
}
