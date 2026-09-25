//! LDAP bind authentication (`ldap` feature).
//!
//! Search-then-bind: a service account finds the user's entry (the login
//! name is filter-escaped), then a bind as that entry's DN with the supplied
//! password proves the credential. Transport is always TLS (`ldaps://` or
//! StartTLS) with certificate verification; the configured CA bundle, else
//! the system roots, anchors trust.

use std::sync::Arc;
use std::time::Duration;

use ldap3::{ldap_escape, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use roci_config::LdapConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

use super::{load_err, AuthError};

pub(crate) struct LdapAuthenticator {
    cfg: LdapConfig,
    bind_password: String,
    tls: Arc<rustls::ClientConfig>,
}

impl LdapAuthenticator {
    pub(crate) fn new(cfg: &LdapConfig) -> Result<Self, AuthError> {
        let bind_password = std::fs::read_to_string(&cfg.bind_password_file)
            .map_err(|e| {
                load_err(
                    "auth.ldap.bind_password_file",
                    format!("reading {}: {e}", cfg.bind_password_file.display()),
                )
            })?
            .trim()
            .to_owned();
        let mut roots = rustls::RootCertStore::empty();
        match &cfg.ca_file {
            Some(path) => {
                let certs = CertificateDer::pem_file_iter(path)
                    .and_then(|it| it.collect::<Result<Vec<_>, _>>())
                    .map_err(|e| {
                        load_err("auth.ldap.ca_file", format!("{}: {e}", path.display()))
                    })?;
                let (added, _) = roots.add_parsable_certificates(certs);
                if added == 0 {
                    return Err(load_err(
                        "auth.ldap.ca_file",
                        format!("{} contains no usable CA certificates", path.display()),
                    ));
                }
            }
            None => {
                roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            }
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            cfg: cfg.clone(),
            bind_password,
            tls: Arc::new(tls),
        })
    }

    /// Authenticate `user`/`password`: `Some(groups)` on success, `None` for
    /// unknown user, wrong password, or an unreachable directory (the latter
    /// logged at `warn`). Bounded by `timeout_secs` end to end.
    pub(crate) async fn authenticate(&self, user: &str, password: &str) -> Option<Vec<String>> {
        // An empty password is an "unauthenticated bind" (RFC 4513 §5.1.2),
        // which many servers accept as success: never send one.
        if password.is_empty() {
            return None;
        }
        let timeout = Duration::from_secs(self.cfg.timeout_secs);
        match tokio::time::timeout(timeout, self.search_and_bind(user, password, timeout)).await {
            Ok(Ok(groups)) => groups,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "ldap authentication failed: directory error");
                None
            }
            Err(_) => {
                tracing::warn!("ldap authentication timed out");
                None
            }
        }
    }

    async fn search_and_bind(
        &self,
        user: &str,
        password: &str,
        timeout: Duration,
    ) -> ldap3::result::Result<Option<Vec<String>>> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(timeout)
            .set_config(Arc::clone(&self.tls))
            .set_starttls(self.cfg.start_tls);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.cfg.url).await?;
        ldap3::drive!(conn);
        ldap.simple_bind(&self.cfg.bind_dn, &self.bind_password)
            .await?
            .success()?;
        let filter = format!(
            "(&({}={}){})",
            self.cfg.user_attribute,
            ldap_escape(user),
            self.cfg.user_filter.as_deref().unwrap_or("")
        );
        let attrs = match &self.cfg.group_attribute {
            Some(a) => vec![a.as_str()],
            None => vec!["1.1"],
        };
        let (entries, _) = ldap
            .search(&self.cfg.base_dn, Scope::Subtree, &filter, attrs)
            .await?
            .success()?;
        // Exactly one entry, or the login name is ambiguous/unknown.
        let Ok([entry]) = <[_; 1]>::try_from(entries) else {
            let _ = ldap.unbind().await;
            return Ok(None);
        };
        let entry = SearchEntry::construct(entry);
        let bound = ldap.simple_bind(&entry.dn, password).await?;
        let _ = ldap.unbind().await;
        if bound.rc != 0 {
            return Ok(None);
        }
        let groups = self.cfg.group_attribute.as_ref().and_then(|a| {
            entry
                .attrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(a))
                .map(|(_, v)| v.clone())
        });
        Ok(Some(groups.unwrap_or_default()))
    }
}
