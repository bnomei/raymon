//! Axum HTTP router for Ray ingest, MCP streamable HTTP, auth, and concurrency limits.
//!
//! Mounts `POST /` for Ray envelope ingest (with JSON-RPC fallback to `/mcp`) and `/mcp` for the
//! MCP streamable HTTP service.

use super::{AppState, CoreBus, CoreState, DynError, DEFAULT_MAX_CONCURRENCY};
use crate::raymon_mcp::{RaymonMcp, RaymonMcpService};
use axum::{
    body::{Body, Bytes},
    extract::DefaultBodyLimit,
    extract::Request as AxumRequest,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use tokio::sync::broadcast;
use tower::ServiceExt;
use tower_http::limit::RequestBodyLimitLayer;

#[derive(Clone)]
struct RouterState {
    app: AppState,
    mcp: RaymonMcpService<CoreState, CoreBus>,
}

#[derive(Clone)]
struct AuthState {
    token: Option<String>,
}

#[derive(Clone)]
struct ConcurrencyState {
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
}

pub(super) fn build_router(
    state: AppState,
    shutdown_tx: broadcast::Sender<()>,
    auth_token: Option<String>,
    max_body_bytes: usize,
    max_query_len: usize,
    allow_mcp_shutdown: bool,
    mcp_redact_payloads: bool,
) -> Result<Router, DynError> {
    let mcp_service =
        RaymonMcp::streamable_http_service_with_shutdown_and_limits_and_shutdown_methods_and_payload_redaction(
            state.core.clone(),
            state.bus.clone(),
            shutdown_tx.clone(),
            max_query_len,
            allow_mcp_shutdown,
            mcp_redact_payloads,
        )?;
    let router_state = RouterState { app: state, mcp: mcp_service.clone() };
    let auth_state = AuthState { token: auth_token };
    let concurrency_state = ConcurrencyState {
        semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(DEFAULT_MAX_CONCURRENCY)),
    };
    let router = Router::new()
        .route("/", post(ingest_or_mcp_handler))
        .route_service("/mcp", mcp_service)
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .route_layer(middleware::from_fn_with_state(auth_state, auth_middleware))
        .route_layer(middleware::from_fn_with_state(concurrency_state, concurrency_middleware))
        .with_state(router_state);
    Ok(router)
}

async fn concurrency_middleware(
    State(state): State<ConcurrencyState>,
    request: AxumRequest,
    next: Next,
) -> axum::response::Response {
    let permit = match state.semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let response = next.run(request).await;
    drop(permit);
    response
}

async fn auth_middleware(
    State(auth): State<AuthState>,
    request: AxumRequest,
    next: Next,
) -> axum::response::Response {
    let Some(expected) = auth.token.as_deref() else {
        return next.run(request).await;
    };

    let bearer = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);
    let header = request
        .headers()
        .get("x-raymon-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    let provided = bearer.or(header);
    if provided == Some(expected) {
        next.run(request).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn ingest_or_mcp_handler(State(state): State<RouterState>, body: Bytes) -> impl IntoResponse {
    let ingestor = state.app.ingestor();
    let body_for_ingest = body.clone();
    let response = match tokio::task::spawn_blocking(move || {
        ingestor.handle(body_for_ingest.as_ref())
    })
    .await
    {
        Ok(response) => response,
        Err(error) => crate::raymon_ingest::IngestResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            error: Some(format!("ingest task failed: {error}")),
        },
    };
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // Some clients POST JSON-RPC to `/` instead of `/mcp`; retry there when ingest rejects the body.
    if response.status == 422 && looks_like_mcp_request(&body) {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()));

        if let Ok(request) = request {
            let response =
                state.mcp.clone().oneshot(request).await.unwrap_or_else(|err| match err {});
            return response.into_response();
        }
    }

    let payload = serde_json::json!({
        "ok": response.error.is_none(),
        "error": response.error,
    });
    (status, Json(payload)).into_response()
}

fn looks_like_mcp_request(body: &Bytes) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    match value {
        serde_json::Value::Object(object) => {
            matches!(object.get("jsonrpc").and_then(|value| value.as_str()), Some("2.0"))
                && object.get("method").is_some()
        }
        serde_json::Value::Array(items) => items.iter().any(|item| {
            item.as_object().is_some_and(|object| {
                matches!(object.get("jsonrpc").and_then(|value| value.as_str()), Some("2.0"))
                    && object.get("method").is_some()
            })
        }),
        _ => false,
    }
}
