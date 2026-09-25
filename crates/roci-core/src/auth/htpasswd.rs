//! bcrypt-only htpasswd file (`user:$2y$…` per line).

use std::collections::HashMap;
use std::path::Path;

pub(crate) enum HtpasswdResult {
    Ok,
    BadPassword,
    UnknownUser,
}

pub(crate) struct Htpasswd {
    users: HashMap<String, String>,
    /// Verified against for unknown users, so a lookup miss costs the same
    /// bcrypt work as a hit (no timing-based user enumeration).
    dummy: String,
}

const BCRYPT_PREFIXES: [&str; 3] = ["$2a$", "$2b$", "$2y$"];

impl Htpasswd {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut users = HashMap::new();
        let mut max_cost = 0;
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (user, hash) = line
                .split_once(':')
                .filter(|(u, _)| !u.is_empty())
                .ok_or_else(|| format!("line {n}: expected `user:bcrypt-hash`"))?;
            let cost = BCRYPT_PREFIXES
                .iter()
                .any(|p| hash.starts_with(p))
                .then(|| hash.get(4..6)?.parse::<u32>().ok())
                .flatten()
                .ok_or_else(|| {
                    format!("line {n}: only bcrypt ($2a$/$2b$/$2y$) hashes are supported")
                })?;
            max_cost = max_cost.max(cost);
            if users.insert(user.to_owned(), hash.to_owned()).is_some() {
                return Err(format!("line {n}: duplicate user `{user}`"));
            }
        }
        // Match the file's work factor so a miss is as slow as a hit.
        let cost = if users.is_empty() { 10 } else { max_cost };
        let dummy = bcrypt::hash("roci-htpasswd-dummy", cost)
            .map_err(|e| format!("bcrypt cost {cost}: {e}"))?;
        Ok(Self { users, dummy })
    }

    /// Check `password` for `user` on the blocking pool (bcrypt is
    /// deliberately slow and would stall the async executor).
    pub(crate) async fn verify(&self, user: &str, password: &str) -> HtpasswdResult {
        let (hash, known) = match self.users.get(user) {
            Some(h) => (h.clone(), true),
            None => (self.dummy.clone(), false),
        };
        let password = password.to_owned();
        let ok =
            tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
                .await
                .unwrap_or(false);
        match (known, ok) {
            (false, _) => HtpasswdResult::UnknownUser,
            (true, true) => HtpasswdResult::Ok,
            (true, false) => HtpasswdResult::BadPassword,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_with_line_numbers() {
        let h = bcrypt::hash("pw", 4).unwrap();
        for (text, needle) in [
            ("alice:{SHA}abc".to_string(), "line 1: only bcrypt"),
            ("\n# c\nalice:$apr1$x$y".to_string(), "line 3: only bcrypt"),
            ("alice:$2y$xx$abc".to_string(), "line 1: only bcrypt"),
            ("nocolon".to_string(), "line 1: expected"),
            (":{h}".to_string(), "line 1: expected"),
            (format!("a:{h}\nb:{h}\na:{h}"), "line 3: duplicate user `a`"),
            (
                "a:$2b$99$abcdefghijklmnopqrstuv".to_string(),
                "bcrypt cost 99",
            ),
        ] {
            let err = Htpasswd::parse(&text).err().expect(&text);
            assert!(err.contains(needle), "{text:?} → {err}");
        }
        assert!(Htpasswd::load(Path::new("/nonexistent/htpasswd"))
            .err()
            .unwrap()
            .contains("reading"));
    }

    #[tokio::test]
    async fn verify_outcomes() {
        let h = bcrypt::hash("pw", 4).unwrap();
        let file = Htpasswd::parse(&format!("# users\n\nalice:{h}\n")).unwrap();
        assert!(file.dummy.starts_with("$2b$04$"));
        assert!(matches!(
            file.verify("alice", "pw").await,
            HtpasswdResult::Ok
        ));
        assert!(matches!(
            file.verify("alice", "nope").await,
            HtpasswdResult::BadPassword
        ));
        assert!(matches!(
            file.verify("mallory", "pw").await,
            HtpasswdResult::UnknownUser
        ));
        // An empty file still yields a dummy hash at the default cost.
        assert!(Htpasswd::parse("").unwrap().dummy.starts_with("$2b$10$"));
    }
}
