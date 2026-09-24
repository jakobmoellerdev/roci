//! `/v2/<name>/<verb>` path parsing and per-method dispatch to the handlers.

use crate::error::ApiError;
use crate::names::RepositoryName;
use crate::{blobs, listing, manifests, uploads, AppState};
use axum::extract::{Path, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use roci_storage::{Digest, Storage};

/// The parsed grammar of a `/v2/<name>/<verb>...` path.
pub(crate) enum Parsed {
    Blob { repo: String, digest: Digest },
    ManifestRef { repo: String, reference: String },
    UploadStart { repo: String },
    UploadSession { repo: String, id: String },
    TagsList { repo: String },
    Referrers { repo: String, digest: Digest },
    Unknown,
}

/// Split `<name>/<tail...>` where the last one or two segments form the verb,
/// **validating** the repository name (and the reference/digest, where the verb
/// carries one) against the dist-spec grammar before any handler runs. An
/// unrecognized path shape yields `Ok(Parsed::Unknown)` (→ 404); a recognized
/// shape with a malformed name/reference/digest yields `Err(ApiError)`.
pub(crate) fn parse_path(rest: &str) -> Result<Parsed, ApiError> {
    let segments: Vec<&str> = rest.split('/').collect();
    let n = segments.len();
    if n < 2 {
        return Ok(Parsed::Unknown);
    }
    // Validate a repository name, surfacing NAME_INVALID.
    let checked_repo = |repo: String| -> Result<String, ApiError> {
        RepositoryName::parse(&repo)?;
        Ok(repo)
    };
    // blobs/uploads/<id?>
    if n >= 3 && segments[n - 3] == "blobs" && segments[n - 2] == "uploads" {
        let repo = checked_repo(segments[..n - 3].join("/"))?;
        let id = segments[n - 1];
        return Ok(if id.is_empty() {
            Parsed::UploadStart { repo }
        } else {
            Parsed::UploadSession {
                repo,
                id: id.to_string(),
            }
        });
    }
    if n >= 2 && segments[n - 2] == "blobs" && segments[n - 1] == "uploads" {
        // trailing slash omitted: `.../blobs/uploads`
        let repo = checked_repo(segments[..n - 2].join("/"))?;
        return Ok(Parsed::UploadStart { repo });
    }
    Ok(match segments[n - 2] {
        "blobs" => {
            let repo = checked_repo(segments[..n - 2].join("/"))?;
            let digest = Digest::parse(segments[n - 1]).map_err(ApiError::from)?;
            Parsed::Blob { repo, digest }
        }
        "manifests" => {
            // The repo name is validated (400 NAME_INVALID); the manifest
            // reference is NOT grammar-rejected here. Per the dist-spec
            // conformance suite, a syntactically-invalid or unknown manifest
            // reference must resolve to 404 MANIFEST_UNKNOWN, not 400 — so the
            // reference flows through and the storage lookup decides.
            let repo = checked_repo(segments[..n - 2].join("/"))?;
            Parsed::ManifestRef {
                repo,
                reference: segments[n - 1].to_string(),
            }
        }
        "tags" if segments[n - 1] == "list" => Parsed::TagsList {
            repo: checked_repo(segments[..n - 2].join("/"))?,
        },
        "referrers" => {
            let repo = checked_repo(segments[..n - 2].join("/"))?;
            let digest = Digest::parse(segments[n - 1]).map_err(ApiError::from)?;
            Parsed::Referrers { repo, digest }
        }
        _ => Parsed::Unknown,
    })
}

pub(crate) async fn get_base() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        "{}",
    )
        .into_response()
}

/// Deserialize the request query string, defaulting on absence or parse failure.
fn query<T: serde::de::DeserializeOwned + Default>(req: &Request) -> T {
    serde_urlencoded::from_str(req.uri().query().unwrap_or("")).unwrap_or_default()
}

/// Parse `/v2/<rest>` and dispatch on (method, path shape). Unknown shapes and
/// method/shape mismatches are NAME_UNKNOWN, exactly as the per-method routers
/// were.
pub(crate) async fn dispatch<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let parsed = parse_path(&rest)?;
    let method = req.method().clone();
    match (&method, parsed) {
        (&Method::GET, Parsed::Blob { repo, digest }) => {
            blobs::get(&st, &repo, &digest, false, req.headers()).await
        }
        (&Method::HEAD, Parsed::Blob { repo, digest }) => {
            blobs::get(&st, &repo, &digest, true, req.headers()).await
        }
        (m, Parsed::ManifestRef { repo, reference }) if *m == Method::GET || *m == Method::HEAD => {
            let head = *m == Method::HEAD;
            manifests::get(&st, &repo, &reference, head, req.headers()).await
        }
        (&Method::GET, Parsed::TagsList { repo }) => {
            let q = query(&req);
            listing::tags(&st, &repo, q).await
        }
        (&Method::GET, Parsed::Referrers { repo, digest }) => {
            let q = query(&req);
            Ok(listing::referrers(&st, &repo, &digest, q).await)
        }
        (&Method::GET, Parsed::UploadSession { repo, id }) => {
            uploads::status(&st, &repo, &id).await
        }
        (&Method::POST, Parsed::UploadStart { repo }) => {
            let q = query(&req);
            uploads::start(&st, &repo, q, req).await
        }
        (&Method::PUT, Parsed::UploadSession { repo, id }) => {
            let q: uploads::UploadQuery = query(&req);
            uploads::finish(&st, &repo, &id, q, req).await
        }
        (&Method::PUT, Parsed::ManifestRef { repo, reference }) => {
            manifests::put(&st, &repo, &reference, req).await
        }
        (&Method::PATCH, Parsed::UploadSession { repo, id }) => {
            uploads::patch(&st, &repo, &id, req).await
        }
        (&Method::DELETE, Parsed::Blob { repo, digest }) => {
            blobs::delete(&st, &repo, &digest).await
        }
        (&Method::DELETE, Parsed::ManifestRef { repo, reference }) => {
            manifests::delete(&st, &repo, &reference).await
        }
        _ => Err(ApiError::name_unknown()),
    }
}
