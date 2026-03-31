//! Axum web server for the Enva Web UI.

mod auth;
mod routes;

use axum::response::IntoResponse;
use axum::Router;
use rust_embed::Embed;
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

#[derive(Embed)]
#[folder = "web/"]
struct Assets;

pub async fn serve(
    vault_path: &str,
    host: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = routes::AppState::new(vault_path.to_string());

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin, _| {
            origin
                .to_str()
                .map(|s| s.starts_with("http://localhost") || s.starts_with("http://127.0.0.1"))
                .unwrap_or(false)
        }))
        .allow_methods(Any)
        .allow_headers(Any);

    let api = routes::api_router(state);

    let app = Router::new()
        .nest("/api", api)
        .fallback(static_handler)
        .layer(cors);

    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("received Ctrl+C, shutting down"); }
        _ = terminate => { tracing::info!("received SIGTERM, shutting down"); }
    }
}

async fn static_handler(uri: axum::http::Uri) -> impl axum::response::IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(axum::http::header::CONTENT_TYPE, mime.as_ref())],
                content.data.into_owned(),
            )
                .into_response()
        }
        None => {
            if let Some(index) = Assets::get("index.html") {
                let mime = mime_guess::from_path("index.html").first_or_octet_stream();
                (
                    [(axum::http::header::CONTENT_TYPE, mime.as_ref())],
                    index.data.into_owned(),
                )
                    .into_response()
            } else {
                (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_contains_index_html() {
        assert!(Assets::get("index.html").is_some());
    }

    #[test]
    fn assets_contains_icon_svg() {
        assert!(Assets::get("icon.svg").is_some());
    }

    #[test]
    fn index_html_uses_current_port_as_default() {
        let index =
            String::from_utf8(Assets::get("index.html").unwrap().data.into_owned()).unwrap();
        assert!(index.contains("function currentPort()"));
        assert!(index.contains("function defaultPortValue()"));
        assert!(index.contains("function activePortValue()"));
        assert!(index.contains("return currentPort() || storedPort() || '8080';"));
        assert!(index.contains("const port = activePortValue();"));
        assert!(index.contains("ptEl.placeholder = defaultPortValue();"));
        assert!(index.contains("settingsPortEl.placeholder = defaultPortValue();"));
    }
}
