mod parsers;

use axum::{extract::Json, routing::post, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::info;

#[derive(Deserialize)]
struct ParseRequest {
    text: String,
    source: Option<String>,
}

#[derive(Serialize)]
struct ParseResponse {
    iocs: Vec<parsers::IoC>,
    count: usize,
    source: String,
}

async fn parse_text(Json(req): Json<ParseRequest>) -> Json<ParseResponse> {
    let iocs = parsers::extract_iocs(&req.text);
    let count = iocs.len();
    let source = req.source.unwrap_or_else(|| "unknown".to_string());

    info!("Extracted {} IoCs from {}", count, source);

    Json(ParseResponse {
        iocs,
        count,
        source,
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/api/v1/parse", post(parse_text))
        .route("/api/v1/health", axum::routing::get(|| async { "healthy" }));

    let listener = TcpListener::bind("0.0.0.0:8085").await.unwrap();
    info!("IoC parser service listening on 0.0.0.0:8085");
    axum::serve(listener, app).await.unwrap();
}
