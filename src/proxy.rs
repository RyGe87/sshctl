//! The jump chain of `ProxyJump`.
//!
//! `ProxyJump bastion,jump2` means: connect to `bastion` first, from there to
//! `jump2`, and only then to the host itself. Every hop may be
//! `user@host:port`, and it may just as well be an alias from your own config
//! — in which case *those* settings apply to that hop.
//!
//! Why this lives on its own: without the chain the doctor can only say "no
//! answer". With the chain it can say *which* hop gives out, and that is
//! usually the only thing you want to know.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

impl Hop {
    /// The way you would type it.
    pub fn label(&self) -> String {
        let mut s = String::new();
        if let Some(u) = &self.user {
            s.push_str(u);
            s.push('@');
        }
        s.push_str(&self.host);
        if let Some(p) = self.port {
            s.push_str(&format!(":{p}"));
        }
        s
    }
}

/// Reads the value of `ProxyJump`. `none` explicitly means: no jump, not even
/// if a more general block does set one.
pub fn parse_chain(value: &str) -> Vec<Hop> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_hop)
        .collect()
}

fn parse_hop(s: &str) -> Hop {
    let (user, rest) = match s.rsplit_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, s),
    };
    // IPv6 in square brackets: [::1]:2222
    if let Some(end) = rest.strip_prefix('[').and_then(|r| r.split_once(']')) {
        let port = end.1.strip_prefix(':').and_then(|p| p.parse().ok());
        return Hop {
            user,
            host: end.0.to_string(),
            port,
        };
    }
    // Only split on exactly one colon: more of them means an IPv6 address
    // without brackets, and by definition that cannot carry a port.
    if rest.matches(':').count() != 1 {
        return Hop {
            user,
            host: rest.to_string(),
            port: None,
        };
    }
    match rest.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => Hop {
            user,
            host: h.to_string(),
            port: p.parse().ok(),
        },
        _ => Hop {
            user,
            host: rest.to_string(),
            port: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_hop() {
        let c = parse_chain("bastion");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].host, "bastion");
        assert_eq!(c[0].user, None);
        assert_eq!(c[0].port, None);
    }

    #[test]
    fn several_hops_in_order() {
        let c = parse_chain("first, second ,third");
        assert_eq!(
            c.iter().map(|h| h.host.as_str()).collect::<Vec<_>>(),
            vec!["first", "second", "third"]
        );
    }

    #[test]
    fn user_and_port() {
        let c = parse_chain("admin@bastion.example:2222");
        assert_eq!(c[0].user.as_deref(), Some("admin"));
        assert_eq!(c[0].host, "bastion.example");
        assert_eq!(c[0].port, Some(2222));
        assert_eq!(c[0].label(), "admin@bastion.example:2222");
    }

    #[test]
    fn none_explicitly_means_no_jump() {
        assert!(parse_chain("none").is_empty());
        assert!(parse_chain("NONE").is_empty());
        assert!(parse_chain("").is_empty());
    }

    #[test]
    fn ipv6_in_square_brackets() {
        let c = parse_chain("[2001:db8::1]:2222");
        assert_eq!(c[0].host, "2001:db8::1");
        assert_eq!(c[0].port, Some(2222));
    }

    #[test]
    fn a_colon_without_digits_is_not_a_port() {
        // An IPv6 address without brackets has no port.
        let c = parse_chain("2001:db8::1");
        assert_eq!(c[0].port, None);
        assert!(c[0].host.contains("db8"));
    }
}
