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
    pub(super) dummy: String,
}

const BCRYPT_PREFIXES: [&str; 3] = ["$2a$", "$2b$", "$2y$"];

impl Htpasswd {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    pub(super) fn parse(text: &str) -> Result<Self, String> {
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
