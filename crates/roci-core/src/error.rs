//! The OCI distribution-spec error vocabulary.
//!
//! [`ErrorCode`] enumerates all 14 canonical codes from the spec error-code
//! table (`spec/distribution-spec/spec.md` §"Error Codes"). [`ApiError`] is the
//! single error type handlers return; it renders the spec JSON envelope
//! `{ "errors": [{ "code", "message" }] }` with the correct HTTP status.
//!
//! `Internal` is the *only* non-spec code: it renders a `500` with the
//! registry-specific `UNKNOWN` code (the spec permits registry-defined codes),
//! preserving the pre-existing internal-error behavior.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use roci_storage::{QuotaScope, StorageError};

/// A dist-spec error code with its canonical wire string and HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BlobUnknown,
    BlobUploadInvalid,
    BlobUploadUnknown,
    DigestInvalid,
    ManifestBlobUnknown,
    ManifestInvalid,
    ManifestUnknown,
    NameInvalid,
    NameUnknown,
    SizeInvalid,
    Unauthorized,
    Denied,
    Unsupported,
    TooManyRequests,
}

impl ErrorCode {
    /// The canonical `SCREAMING_SNAKE` wire string (spec error-code table).
    pub fn wire(self) -> &'static str {
        match self {
            ErrorCode::BlobUnknown => "BLOB_UNKNOWN",
            ErrorCode::BlobUploadInvalid => "BLOB_UPLOAD_INVALID",
            ErrorCode::BlobUploadUnknown => "BLOB_UPLOAD_UNKNOWN",
            ErrorCode::DigestInvalid => "DIGEST_INVALID",
            ErrorCode::ManifestBlobUnknown => "MANIFEST_BLOB_UNKNOWN",
            ErrorCode::ManifestInvalid => "MANIFEST_INVALID",
            ErrorCode::ManifestUnknown => "MANIFEST_UNKNOWN",
            ErrorCode::NameInvalid => "NAME_INVALID",
            ErrorCode::NameUnknown => "NAME_UNKNOWN",
            ErrorCode::SizeInvalid => "SIZE_INVALID",
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::Denied => "DENIED",
            ErrorCode::Unsupported => "UNSUPPORTED",
            ErrorCode::TooManyRequests => "TOOMANYREQUESTS",
        }
    }

    /// The HTTP status the spec maps this code to.
    pub fn status(self) -> StatusCode {
        match self {
            ErrorCode::NameUnknown
            | ErrorCode::ManifestUnknown
            | ErrorCode::BlobUnknown
            | ErrorCode::BlobUploadUnknown => StatusCode::NOT_FOUND,
            ErrorCode::NameInvalid
            | ErrorCode::DigestInvalid
            | ErrorCode::SizeInvalid
            | ErrorCode::ManifestInvalid
            | ErrorCode::ManifestBlobUnknown
            | ErrorCode::BlobUploadInvalid => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Denied => StatusCode::FORBIDDEN,
            ErrorCode::Unsupported => StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

/// An error rendered as the dist-spec JSON envelope. `Spec` carries one of the
/// 14 canonical codes; `Internal` is the sole non-spec (500 / `UNKNOWN`) case;
/// `PayloadTooLarge` renders `413` with the `SIZE_INVALID` code (the dist-spec
/// binds end-7 body-limit rejection to `413`, spec endpoint table);
/// `InsufficientStorage` renders `507` with `DENIED` when the registry-wide
/// storage quota is exhausted (a 5xx body is not bound to the code table).
#[derive(Debug, Clone)]
pub enum ApiError {
    Spec { code: ErrorCode, message: String },
    Internal(String),
    PayloadTooLarge(String),
    InsufficientStorage(String),
}

impl ApiError {
    /// Construct a spec error with an explicit code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError::Spec {
            code,
            message: message.into(),
        }
    }

    pub fn name_invalid(message: impl Into<String>) -> Self {
        ApiError::new(ErrorCode::NameInvalid, message)
    }
    pub fn name_unknown() -> Self {
        ApiError::new(
            ErrorCode::NameUnknown,
            "repository name not known to registry",
        )
    }
    pub fn digest_invalid(message: impl Into<String>) -> Self {
        ApiError::new(ErrorCode::DigestInvalid, message)
    }
    pub fn manifest_invalid(message: impl Into<String>) -> Self {
        ApiError::new(ErrorCode::ManifestInvalid, message)
    }
    pub fn manifest_blob_unknown(message: impl Into<String>) -> Self {
        ApiError::new(ErrorCode::ManifestBlobUnknown, message)
    }
    pub fn manifest_unknown() -> Self {
        ApiError::new(ErrorCode::ManifestUnknown, "manifest unknown to registry")
    }
    pub fn blob_unknown() -> Self {
        ApiError::new(ErrorCode::BlobUnknown, "blob unknown to registry")
    }
    pub fn unsupported() -> Self {
        ApiError::new(ErrorCode::Unsupported, "the operation is unsupported")
    }
    /// A body exceeding the accepted size: `413` with the `SIZE_INVALID` code.
    pub fn payload_too_large(message: impl Into<String>) -> Self {
        ApiError::PayloadTooLarge(message.into())
    }

    /// The HTTP status of this error.
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::Spec { code, .. } => code.status(),
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::InsufficientStorage(_) => StatusCode::INSUFFICIENT_STORAGE,
        }
    }

    /// The wire code string (`UNKNOWN` for the internal case).
    pub fn code(&self) -> &str {
        match self {
            ApiError::Spec { code, .. } => code.wire(),
            ApiError::Internal(_) => "UNKNOWN",
            ApiError::PayloadTooLarge(_) => ErrorCode::SizeInvalid.wire(),
            ApiError::InsufficientStorage(_) => ErrorCode::Denied.wire(),
        }
    }

    fn message(&self) -> &str {
        match self {
            ApiError::Spec { message, .. } => message,
            ApiError::Internal(m) => m,
            ApiError::PayloadTooLarge(m) => m,
            ApiError::InsufficientStorage(m) => m,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = self.code();
        let status = self.status();

        // Record error on the current span + increment the error counter.
        let span = tracing::Span::current();
        span.record("error.type", code);
        span.record("otel.status_code", "ERROR");
        roci_telemetry::record_error(code);

        let body = serde_json::json!({
            "errors": [{ "code": code, "message": self.message() }]
        });
        (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response()
    }
}

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        match e {
            // Generic default; blob/manifest endpoints override 404s to
            // BLOB_UNKNOWN / MANIFEST_UNKNOWN at their call sites.
            StorageError::NotFound => ApiError::name_unknown(),
            StorageError::BadDigest(d) => ApiError::digest_invalid(format!("invalid digest: {d}")),
            StorageError::DigestMismatch { expected, actual } => ApiError::digest_invalid(format!(
                "digest mismatch: expected {expected}, got {actual}"
            )),
            StorageError::BadPath(p) => {
                ApiError::name_invalid(format!("unsafe path component: {p}"))
            }
            // The upload endpoints translate this to a 416 with a Range header
            // at the call site; the generic fallback is a 400 BLOB_UPLOAD_INVALID.
            StorageError::RangeNotSatisfiable { .. } => ApiError::new(
                ErrorCode::BlobUploadInvalid,
                "content range does not match offset",
            ),
            StorageError::TooLarge { limit, actual } => ApiError::payload_too_large(format!(
                "upload size {actual} exceeds maximum blob size {limit}"
            )),
            // A repository over its quota is a client-side size problem (413);
            // an exhausted registry-wide quota is the server's (507).
            e @ StorageError::QuotaExceeded {
                scope: QuotaScope::Repository,
                ..
            } => ApiError::payload_too_large(e.to_string()),
            e @ StorageError::QuotaExceeded {
                scope: QuotaScope::Total,
                ..
            } => ApiError::InsufficientStorage(e.to_string()),
            e @ StorageError::TooManySessions { .. } => {
                ApiError::new(ErrorCode::TooManyRequests, e.to_string())
            }
            StorageError::MissingReference(d) => {
                ApiError::manifest_blob_unknown(format!("referenced blob {d} is not present"))
            }
            StorageError::Io(_) => ApiError::Internal("internal error".to_string()),
        }
    }
}

/// Map `StorageError::NotFound` to `unknown()` and every other error through `From`.
pub(crate) fn not_found_as(unknown: fn() -> ApiError) -> impl FnOnce(StorageError) -> ApiError {
    move |e| match e {
        StorageError::NotFound => unknown(),
        other => ApiError::from(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_wire_and_status() {
        let all = [
            ErrorCode::BlobUnknown,
            ErrorCode::BlobUploadInvalid,
            ErrorCode::BlobUploadUnknown,
            ErrorCode::DigestInvalid,
            ErrorCode::ManifestBlobUnknown,
            ErrorCode::ManifestInvalid,
            ErrorCode::ManifestUnknown,
            ErrorCode::NameInvalid,
            ErrorCode::NameUnknown,
            ErrorCode::SizeInvalid,
            ErrorCode::Unauthorized,
            ErrorCode::Denied,
            ErrorCode::Unsupported,
            ErrorCode::TooManyRequests,
        ];
        // All 14 codes present; wire strings are SCREAMING_SNAKE and unique.
        assert_eq!(all.len(), 14);
        let mut seen = std::collections::HashSet::new();
        for c in all {
            let w = c.wire();
            assert!(w.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_'));
            assert!(seen.insert(w), "duplicate wire string {w}");
            let _ = c.status();
        }
    }

    #[test]
    fn status_mapping_is_correct() {
        assert_eq!(ErrorCode::NameInvalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(ErrorCode::NameUnknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(ErrorCode::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ErrorCode::Denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            ErrorCode::Unsupported.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            ErrorCode::TooManyRequests.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn internal_renders_500_unknown() {
        let e = ApiError::Internal("boom".into());
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(e.code(), "UNKNOWN");
    }

    #[test]
    fn storage_err_maps_to_codes() {
        assert_eq!(
            ApiError::from(StorageError::NotFound).code(),
            "NAME_UNKNOWN"
        );
        assert_eq!(
            ApiError::from(StorageError::BadDigest("x".into())).code(),
            "DIGEST_INVALID"
        );
        assert_eq!(
            ApiError::from(StorageError::BadPath("..".into())).code(),
            "NAME_INVALID"
        );
        assert_eq!(
            ApiError::from(StorageError::DigestMismatch {
                expected: "a".into(),
                actual: "b".into()
            })
            .code(),
            "DIGEST_INVALID"
        );
        assert_eq!(
            ApiError::from(StorageError::RangeNotSatisfiable {
                expected: 3,
                got: 0
            })
            .code(),
            "BLOB_UPLOAD_INVALID"
        );
        let io = StorageError::Io(std::io::Error::other("x"));
        assert_eq!(ApiError::from(io).code(), "UNKNOWN");
    }

    #[test]
    fn quota_and_session_caps_map_to_their_statuses() {
        let quota = |scope| {
            ApiError::from(StorageError::QuotaExceeded {
                scope,
                limit: 1,
                requested: 2,
            })
        };
        let repo = quota(QuotaScope::Repository);
        assert_eq!(
            (repo.status(), repo.code()),
            (StatusCode::PAYLOAD_TOO_LARGE, "SIZE_INVALID")
        );
        let total = quota(QuotaScope::Total);
        assert_eq!(
            (total.status(), total.code()),
            (StatusCode::INSUFFICIENT_STORAGE, "DENIED")
        );
        assert_eq!(
            total.clone().into_response().status(),
            StatusCode::INSUFFICIENT_STORAGE
        );
        let sessions = ApiError::from(StorageError::TooManySessions { limit: 3 });
        assert_eq!(
            (sessions.status(), sessions.code()),
            (StatusCode::TOO_MANY_REQUESTS, "TOOMANYREQUESTS")
        );
    }

    #[test]
    fn envelope_shape() {
        let resp = ApiError::name_invalid("bad").into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
