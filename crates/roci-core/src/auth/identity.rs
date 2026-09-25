//! Identity of a verified mTLS client certificate.

use x509_parser::extensions::GeneralName;

/// Longest accepted identity.
const MAX_IDENTITY_LEN: usize = 255;

fn usable(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_IDENTITY_LEN && !id.chars().any(char::is_control)
}

/// The user name a verified client leaf certificate authenticates: its
/// Subject CN, else its first DNS SAN. `None` (→ Anonymous) when neither
/// yields a usable name (non-empty, ≤255 bytes, no control characters).
pub fn client_cert_identity(leaf_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(leaf_der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .filter_map(|a| a.as_str().ok())
        .find(|s| usable(s));
    let id = cn.or_else(|| {
        let san = cert.subject_alternative_name().ok().flatten()?;
        san.value.general_names.iter().find_map(|g| match g {
            GeneralName::DNSName(d) if usable(d) => Some(*d),
            _ => None,
        })
    });
    if id.is_none() {
        tracing::debug!("client certificate carries no usable CN or DNS SAN; anonymous");
    }
    id.map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn cert(cn: Option<&str>, dns: &[&str]) -> Vec<u8> {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        if let Some(cn) = cn {
            dn.push(DnType::CommonName, cn);
        }
        p.distinguished_name = dn;
        p.subject_alt_names = dns
            .iter()
            .map(|d| match d.parse() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName((*d).try_into().unwrap()),
            })
            .collect();
        let kp = KeyPair::generate().unwrap();
        p.self_signed(&kp).unwrap().der().to_vec()
    }

    #[test]
    fn cn_then_dns_san_then_none() {
        assert_eq!(
            client_cert_identity(&cert(Some("alice"), &["svc.example"])).as_deref(),
            Some("alice")
        );
        // Non-DNS SAN entries are skipped.
        assert_eq!(
            client_cert_identity(&cert(None, &["10.0.0.1", "svc.example", "b.example"])).as_deref(),
            Some("svc.example")
        );
        // An unusable CN falls back to the SAN.
        let long = "x".repeat(256);
        assert_eq!(
            client_cert_identity(&cert(Some(&long), &["svc.example"])).as_deref(),
            Some("svc.example")
        );
        assert_eq!(client_cert_identity(&cert(None, &[])), None);
        assert_eq!(client_cert_identity(&cert(Some("a\u{7}b"), &[])), None);
        assert_eq!(client_cert_identity(b"not a certificate"), None);
    }
}
