//! Example: fetch any H33 API endpoint and verify the response.
//!
//! Requires the `reqwest-support` feature:
//!
//! ```bash
//! cargo run --example verify_url --features reqwest-support -- https://api.h33.ai/health
//! ```
//!
//! Note: `/health` is in the server's skip list and will NOT carry
//! attestation headers. Try a substantive endpoint like
//! `https://api.h33.ai/v1/substrate/public-keys` or
//! `https://api.h33.ai/openapi.json` instead.

// Example code uses eprintln!/println! and exits with error codes;
// relax the library-side strict lints that would flag those.
#![allow(
    missing_docs,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

use h33_substrate_verifier::{headers::headers_from_reqwest, Verifier};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let url = std::env::args().nth(1).unwrap_or_else(|| {
        "https://api.h33.ai/v1/substrate/public-keys".to_string()
    });

    eprintln!("GET {url}");
    let response = match reqwest::get(&url).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("request failed: {e}");
            return ExitCode::from(2);
        }
    };

    let status = response.status();
    eprintln!("HTTP {status}");

    let headers_owned = match headers_from_reqwest(&response) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("response is missing one or more X-H33-* headers: {e}");
            eprintln!("(endpoints in the server's skip list — /health, /ready, /metrics, /v1/auth/speedtest/* — do not carry attestation headers by design)");
            return ExitCode::from(3);
        }
    };

    let body_bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("body read failed: {e}");
            return ExitCode::from(2);
        }
    };

    let headers = headers_owned.borrow();
    let verifier = Verifier::new();

    match verifier.verify(&body_bytes, &headers) {
        Ok(result) => {
            println!("{}", result.summary());
            println!("  body_hash_matches     = {}", result.body_hash_matches);
            println!("  receipt_well_formed   = {}", result.receipt_well_formed);
            println!("  algorithms_match_flags = {}", result.algorithms_match_flags);
            println!("  timestamps_agree      = {}", result.timestamps_agree);
            if result.is_valid() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("verifier error: {e}");
            ExitCode::from(2)
        }
    }
}
