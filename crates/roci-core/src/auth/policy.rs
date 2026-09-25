//! Identity-based access control: `[access_control]` compiled for lookup.
//!
//! Each repository is governed by exactly one rule — the most specific glob
//! matching it (most literal bytes, then fewest wildcards, then earliest
//! declared) — so a narrow rule can *remove* grants a broad one gives.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use roci_config::AccessControlConfig;

use super::ActionSet;

/// One glob token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Lit(u8),
    /// `*`: any run of bytes within one path component.
    Star,
    /// `**` as the final component: any run of bytes, `/` included.
    AnyTail,
    /// `**/` before another component: zero or more whole components.
    AnyDirs,
}

fn tokenize(pattern: &str) -> Vec<Tok> {
    let comps: Vec<&str> = pattern.split('/').collect();
    let mut toks = Vec::with_capacity(pattern.len());
    let mut after_dirs = false;
    for (i, comp) in comps.iter().enumerate() {
        if i > 0 && !after_dirs {
            toks.push(Tok::Lit(b'/'));
        }
        after_dirs = false;
        if *comp == "**" {
            if i + 1 == comps.len() {
                toks.push(Tok::AnyTail);
            } else {
                toks.push(Tok::AnyDirs);
                after_dirs = true;
            }
            continue;
        }
        toks.extend(
            comp.bytes()
                .map(|b| if b == b'*' { Tok::Star } else { Tok::Lit(b) }),
        );
    }
    toks
}

/// Whether `name` matches the tokenized glob: an O(tokens · len) DP over
/// suffixes, one row per token.
fn glob_match(toks: &[Tok], name: &[u8]) -> bool {
    let n = name.len();
    // next[j]: tokens after the current one match name[j..].
    let mut next = vec![false; n + 1];
    next[n] = true;
    let mut cur = vec![false; n + 1];
    for tok in toks.iter().rev() {
        cur[n] = matches!(tok, Tok::Star | Tok::AnyTail | Tok::AnyDirs) && next[n];
        let mut dirs = false;
        for j in (0..n).rev() {
            cur[j] = match tok {
                Tok::Lit(c) => name[j] == *c && next[j + 1],
                Tok::Star => next[j] || (name[j] != b'/' && cur[j + 1]),
                Tok::AnyTail => next[j] || cur[j + 1],
                Tok::AnyDirs => {
                    // Consume `name[j..=k]` ending in `/` for some k ≥ j.
                    dirs = dirs || (name[j] == b'/' && next[j + 1]);
                    next[j] || dirs
                }
            };
        }
        std::mem::swap(&mut next, &mut cur);
    }
    next[0]
}

#[derive(Debug)]
struct Rule {
    toks: Vec<Tok>,
    /// Non-wildcard pattern bytes: the primary specificity key.
    literal_len: usize,
    /// Wildcard tokens: the tie-break (fewer is more specific).
    stars: usize,
    anonymous: ActionSet,
    authenticated: ActionSet,
    /// `(users, groups, actions)` per identity policy.
    policies: Vec<(HashSet<String>, HashSet<String>, ActionSet)>,
}

/// A compiled `[access_control]` section.
#[derive(Debug)]
pub(crate) struct AccessPolicy {
    admins: HashSet<String>,
    /// Config `groups`, inverted: user → the groups listing them.
    user_groups: HashMap<String, Vec<String>>,
    rules: Vec<Rule>,
}

impl AccessPolicy {
    pub(crate) fn compile(ac: &AccessControlConfig) -> Arc<Self> {
        let mut user_groups: HashMap<String, Vec<String>> = HashMap::new();
        for (group, users) in &ac.groups {
            for u in users {
                user_groups
                    .entry(u.clone())
                    .or_default()
                    .push(group.clone());
            }
        }
        let rules = ac
            .repositories
            .iter()
            .map(|r| {
                let toks = tokenize(&r.pattern);
                Rule {
                    literal_len: toks.iter().filter(|t| matches!(t, Tok::Lit(_))).count(),
                    stars: toks.iter().filter(|t| !matches!(t, Tok::Lit(_))).count(),
                    toks,
                    anonymous: ActionSet::from_actions(&r.anonymous),
                    authenticated: ActionSet::from_actions(&r.authenticated),
                    policies: r
                        .policies
                        .iter()
                        .map(|p| {
                            (
                                p.users.iter().cloned().collect(),
                                p.groups.iter().cloned().collect(),
                                ActionSet::from_actions(&p.actions),
                            )
                        })
                        .collect(),
                }
            })
            .collect();
        Arc::new(Self {
            admins: ac.admins.iter().cloned().collect(),
            user_groups,
            rules,
        })
    }

    fn winning_rule(&self, repo: &str) -> Option<&Rule> {
        let mut best: Option<&Rule> = None;
        for r in &self.rules {
            if !glob_match(&r.toks, repo.as_bytes()) {
                continue;
            }
            let better = best.is_none_or(|b| {
                (r.literal_len, std::cmp::Reverse(r.stars))
                    > (b.literal_len, std::cmp::Reverse(b.stars))
            });
            if better {
                best = Some(r);
            }
        }
        best
    }

    /// The actions `name` (`None` = anonymous) holds on `repo`.
    pub(crate) fn grants(
        &self,
        name: Option<&str>,
        ldap_groups: &[String],
        repo: &str,
    ) -> ActionSet {
        if name.is_some_and(|n| self.admins.contains(n)) {
            return ActionSet::ALL;
        }
        let Some(rule) = self.winning_rule(repo) else {
            return ActionSet::NONE;
        };
        let Some(name) = name else {
            return rule.anonymous;
        };
        let config_groups = self.user_groups.get(name).map_or(&[][..], Vec::as_slice);
        rule.policies
            .iter()
            .filter(|(users, groups, _)| {
                users.contains(name)
                    || config_groups
                        .iter()
                        .chain(ldap_groups)
                        .any(|g| groups.contains(g))
            })
            .fold(rule.anonymous.union(rule.authenticated), |s, (_, _, a)| {
                s.union(*a)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roci_config::{Action, IdentityPolicy, RepositoryPolicy};

    fn m(pattern: &str, name: &str) -> bool {
        glob_match(&tokenize(pattern), name.as_bytes())
    }

    #[test]
    fn glob_semantics() {
        for (p, name, want) in [
            ("a", "a", true),
            ("a", "ab", false),
            ("*", "app", true),
            ("*", "team/app", false),
            ("team/*", "team/app", true),
            ("team/*", "team/app/x", false),
            ("team/*-dev", "team/app-dev", true),
            ("team/*-dev", "team/app-prod", false),
            ("**", "anything/at/all", true),
            ("team/**", "team/a", true),
            ("team/**", "team/a/b", true),
            ("team/**", "team", false),
            ("team/**", "teams/a", false),
            ("**/b", "b", true),
            ("**/b", "a/b", true),
            ("**/b", "a/c/b", true),
            ("**/b", "ab", false),
            ("a/**/b", "a/b", true),
            ("a/**/b", "a/x/y/b", true),
            ("a/**/b", "a/xb", false),
            ("*/**", "a/b/c", true),
            ("*/**", "a", false),
        ] {
            assert_eq!(m(p, name), want, "{p} vs {name}");
        }
    }

    fn rule(
        pattern: &str,
        anonymous: &[Action],
        policies: Vec<IdentityPolicy>,
    ) -> RepositoryPolicy {
        RepositoryPolicy {
            pattern: pattern.into(),
            anonymous: anonymous.to_vec(),
            authenticated: vec![],
            policies,
        }
    }

    fn users(u: &[&str], actions: &[Action]) -> IdentityPolicy {
        IdentityPolicy {
            users: u.iter().map(|s| s.to_string()).collect(),
            groups: vec![],
            actions: actions.to_vec(),
        }
    }

    #[test]
    fn most_specific_rule_wins_alone() {
        let ac = AccessControlConfig {
            repositories: vec![
                rule("**", &[Action::Pull], vec![]),
                rule("team/**", &[], vec![users(&["alice"], &[Action::Push])]),
                rule("team/secret", &[], vec![]),
                // Same literal count as `team/*x` but more wildcards: loses.
                rule("team/*x*", &[Action::Delete], vec![]),
                rule("team/*x", &[Action::Pull], vec![]),
            ],
            ..Default::default()
        };
        let p = AccessPolicy::compile(&ac);
        // `**` alone governs `other`.
        assert_eq!(p.grants(None, &[], "other"), ActionSet::of(Action::Pull));
        // `team/**` replaces `**`: anonymous loses pull, alice gains push.
        assert_eq!(p.grants(None, &[], "team/app"), ActionSet::NONE);
        assert_eq!(
            p.grants(Some("alice"), &[], "team/app"),
            ActionSet::of(Action::Push)
        );
        // `team/secret` is more specific still and grants nothing.
        assert_eq!(p.grants(Some("alice"), &[], "team/secret"), ActionSet::NONE);
        assert_eq!(p.grants(None, &[], "team/ax"), ActionSet::of(Action::Pull));
    }

    #[test]
    fn declaration_order_breaks_full_ties() {
        let ac = AccessControlConfig {
            repositories: vec![
                rule("a/*", &[Action::Pull], vec![]),
                rule("*/b", &[Action::Delete], vec![]),
            ],
            ..Default::default()
        };
        let p = AccessPolicy::compile(&ac);
        assert_eq!(p.grants(None, &[], "a/b"), ActionSet::of(Action::Pull));
    }

    #[test]
    fn grants_union_identity_sources() {
        let ac = AccessControlConfig {
            admins: vec!["root".into()],
            groups: [("devs".to_string(), vec!["bob".to_string()])].into(),
            repositories: vec![RepositoryPolicy {
                pattern: "r".into(),
                anonymous: vec![Action::Pull],
                authenticated: vec![],
                policies: vec![
                    IdentityPolicy {
                        users: vec![],
                        groups: vec!["devs".into()],
                        actions: vec![Action::Push],
                    },
                    IdentityPolicy {
                        users: vec![],
                        groups: vec!["cn=ops,dc=x".into()],
                        actions: vec![Action::Delete],
                    },
                ],
            }],
        };
        let p = AccessPolicy::compile(&ac);
        let pull_push = ActionSet::from_actions(&[Action::Pull, Action::Push]);
        assert_eq!(p.grants(Some("bob"), &[], "r"), pull_push);
        assert_eq!(
            p.grants(Some("carol"), &[], "r"),
            ActionSet::of(Action::Pull)
        );
        assert_eq!(
            p.grants(Some("carol"), &["cn=ops,dc=x".into()], "r"),
            ActionSet::from_actions(&[Action::Pull, Action::Delete])
        );
        // Admins hold everything, even where no rule matches.
        assert_eq!(p.grants(Some("root"), &[], "unmatched"), ActionSet::ALL);
        assert_eq!(p.grants(Some("bob"), &[], "unmatched"), ActionSet::NONE);
    }
}
