//! OCI distribution-spec error vocabulary (§"Error Codes").

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use roci_storage::{QuotaScope, StorageError};

/// Dist-spec error code with canonical wire string and HTTP status.
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
    const fn parts(self) -> (&'static str, StatusCode) {
        match self {
            ErrorCode::BlobUnknown => ("BLOB_UNKNOWN", StatusCode::NOT_FOUND),
            ErrorCode::BlobUploadInvalid => ("BLOB_UPLOAD_INVALID", StatusCode::BAD_REQUEST),
            ErrorCode::BlobUploadUnknown => ("BLOB_UPLOAD_UNKNOWN", StatusCode::NOT_FOUND),
            ErrorCode::DigestInvalid => ("DIGEST_INVALID", StatusCode::BAD_REQUEST),
            ErrorCode::ManifestBlobUnknown => ("MANIFEST_BLOB_UNKNOWN", StatusCode::BAD_REQUEST),
            ErrorCode::ManifestInvalid => ("MANIFEST_INVALID", StatusCode::BAD_REQUEST),
            ErrorCode::ManifestUnknown => ("MANIFEST_UNKNOWN", StatusCode::NOT_FOUND),
            ErrorCode::NameInvalid => ("NAME_INVALID", StatusCode::BAD_REQUEST),
            ErrorCode::NameUnknown => ("NAME_UNKNOWN", StatusCode::NOT_FOUND),
            ErrorCode::SizeInvalid => ("SIZE_INVALID", StatusCode::BAD_REQUEST),
            ErrorCode::Unauthorized => ("UNAUTHORIZED", StatusCode::UNAUTHORIZED),
            ErrorCode::Denied => ("DENIED", StatusCode::FORBIDDEN),
            ErrorCode::Unsupported => ("UNSUPPORTED", StatusCode::METHOD_NOT_ALLOWED),
            ErrorCode::TooManyRequests => ("TOOMANYREQUESTS", StatusCode::TOO_MANY_REQUESTS),
        }
    }

    /// The canonical `SCREAMING_SNAKE` wire string (spec error-code table).
    pub fn wire(self) -> &'static str {
        self.parts().0
    }

    /// The HTTP status the spec maps this code to.
    pub fn status(self) -> StatusCode {
        self.parts().1
    }
}

/// Dist-spec error response envelope.
#[derive(Debug, Clone)]
pub enum ApiError {
    Spec {
        code: ErrorCode,
        message: String,
    },
    Internal(String),
    PayloadTooLarge(String),
    InsufficientStorage(String),
    Unauthenticated {
        message: String,
        challenge: Option<HeaderValue>,
    },
    TooEarly,
    /// Storage backend temporarily unreachable (e.g. S3 bucket not yet
    /// replicated). Renders `503 Service Unavailable` with `UNKNOWN`.
    Unavailable(String),
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError::Spec {
            code,
            message: message.into(),
        }
    }

    pub fn name_invalid(message: impl Into<String>) -> Self {
        ApiError::new(ErrorCode::NameInvalid, message)
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
    pub fn payload_too_large(message: impl Into<String>) -> Self {
        ApiError::PayloadTooLarge(message.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::Spec { code, .. } => code.status(),
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::InsufficientStorage(_) => StatusCode::INSUFFICIENT_STORAGE,
            ApiError::Unauthenticated { .. } => StatusCode::UNAUTHORIZED,
            ApiError::TooEarly => StatusCode::from_u16(425).expect("425 is a valid status"),
            ApiError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn code(&self) -> &str {
        match self {
            ApiError::Spec { code, .. } => code.wire(),
            ApiError::Internal(_) | ApiError::Unavailable(_) => "UNKNOWN",
            ApiError::PayloadTooLarge(_) => ErrorCode::SizeInvalid.wire(),
            ApiError::InsufficientStorage(_) | ApiError::TooEarly => ErrorCode::Denied.wire(),
            ApiError::Unauthenticated { .. } => ErrorCode::Unauthorized.wire(),
        }
    }

    fn message(&self) -> &str {
        match self {
            ApiError::Spec { message, .. } => message,
            ApiError::Internal(m) | ApiError::Unavailable(m) => m,
            ApiError::PayloadTooLarge(m) => m,
            ApiError::InsufficientStorage(m) => m,
            ApiError::Unauthenticated { message, .. } => message,
            ApiError::TooEarly => {
                "request sent in TLS early data; retry after the handshake completes"
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = self.code();
        let status = self.status();

        let span = tracing::Span::current();
        span.record("error.type", code);
        span.record("otel.status_code", "ERROR");
        roci_telemetry::record_error(code);

        let body = serde_json::json!({
            "errors": [{ "code": code, "message": self.message() }]
        });
        let mut resp = (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response();
        if let ApiError::Unauthenticated {
            challenge: Some(c), ..
        } = self
        {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, c);
        }
        resp
    }
}

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::NotFound => ApiError::new(
                ErrorCode::NameUnknown,
                "repository name not known to registry",
            ),
            StorageError::BadDigest(d) => ApiError::digest_invalid(format!("invalid digest: {d}")),
            StorageError::DigestMismatch { expected, actual } => ApiError::digest_invalid(format!(
                "digest mismatch: expected {expected}, got {actual}"
            )),
            StorageError::BadPath(p) => {
                ApiError::name_invalid(format!("unsafe path component: {p}"))
            }
            StorageError::RangeNotSatisfiable { .. } => ApiError::new(
                ErrorCode::BlobUploadInvalid,
                "content range does not match offset",
            ),
            StorageError::TooLarge { limit, actual } => ApiError::payload_too_large(format!(
                "upload size {actual} exceeds maximum blob size {limit}"
            )),
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
            StorageError::Unavailable(detail) => {
                tracing::warn!(error = %detail, "storage backend unavailable");
                ApiError::Unavailable("storage temporarily unavailable".to_string())
            }
        }
    }
}

/// Map `StorageError::NotFound` to `unknown()` and every other error through `From`.
pub(crate) fn not_found_as(
    unknown: impl FnOnce() -> ApiError,
) -> impl FnOnce(StorageError) -> ApiError {
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
        let all: [(ErrorCode, &str, StatusCode); 14] = [
            (
                ErrorCode::BlobUnknown,
                "BLOB_UNKNOWN",
                StatusCode::NOT_FOUND,
            ),
            (
                ErrorCode::BlobUploadInvalid,
                "BLOB_UPLOAD_INVALID",
                StatusCode::BAD_REQUEST,
            ),
            (
                ErrorCode::BlobUploadUnknown,
                "BLOB_UPLOAD_UNKNOWN",
                StatusCode::NOT_FOUND,
            ),
            (
                ErrorCode::DigestInvalid,
                "DIGEST_INVALID",
                StatusCode::BAD_REQUEST,
            ),
            (
                ErrorCode::ManifestBlobUnknown,
                "MANIFEST_BLOB_UNKNOWN",
                StatusCode::BAD_REQUEST,
            ),
            (
                ErrorCode::ManifestInvalid,
                "MANIFEST_INVALID",
                StatusCode::BAD_REQUEST,
            ),
            (
                ErrorCode::ManifestUnknown,
                "MANIFEST_UNKNOWN",
                StatusCode::NOT_FOUND,
            ),
            (
                ErrorCode::NameInvalid,
                "NAME_INVALID",
                StatusCode::BAD_REQUEST,
            ),
            (
                ErrorCode::NameUnknown,
                "NAME_UNKNOWN",
                StatusCode::NOT_FOUND,
            ),
            (
                ErrorCode::SizeInvalid,
                "SIZE_INVALID",
                StatusCode::BAD_REQUEST,
            ),
            (
                ErrorCode::Unauthorized,
                "UNAUTHORIZED",
                StatusCode::UNAUTHORIZED,
            ),
            (ErrorCode::Denied, "DENIED", StatusCode::FORBIDDEN),
            (
                ErrorCode::Unsupported,
                "UNSUPPORTED",
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                ErrorCode::TooManyRequests,
                "TOOMANYREQUESTS",
                StatusCode::TOO_MANY_REQUESTS,
            ),
        ];
        let mut seen = std::collections::HashSet::new();
        for (code, wire, status) in all {
            assert_eq!(code.wire(), wire, "{wire}");
            assert_eq!(code.status(), status, "{wire}");
            assert!(
                wire.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_'),
                "{wire}"
            );
            assert!(seen.insert(wire), "duplicate wire string {wire}");
        }
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

    #[test]
    fn too_early_renders_425_denied() {
        let e = ApiError::TooEarly;
        assert_eq!(e.status(), StatusCode::from_u16(425).unwrap(), "status");
        assert_eq!(e.code(), "DENIED", "code");
    }

    #[test]
    fn missing_reference_maps_to_manifest_blob_unknown() {
        let e = ApiError::from(StorageError::MissingReference("sha256:abc".into()));
        assert_eq!(e.status(), StatusCode::BAD_REQUEST, "status");
        assert_eq!(e.code(), "MANIFEST_BLOB_UNKNOWN", "code");
    }

    #[test]
    fn unavailable_maps_to_503() {
        let e = ApiError::from(StorageError::Unavailable("s3 down".into()));
        assert_eq!(e.status(), StatusCode::SERVICE_UNAVAILABLE, "status");
        assert_eq!(e.code(), "UNKNOWN", "code");
    }
}
