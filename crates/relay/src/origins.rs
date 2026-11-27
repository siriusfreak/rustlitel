//! The public origins the relay answers on.
//!
//! One relay may be reachable under several names (e.g. a domestic and a
//! foreign entry point to the same pod). `RUSTLITEL_PUBLIC_ORIGIN` is a
//! comma-separated list; a single value keeps working as before. Each request
//! is served for the origin its `Host` names, if that origin is listed, else for
//! the first one, so links, the OIDC redirect and agent installers stay on the
//! name the browser used.

/// Parse `RUSTLITEL_PUBLIC_ORIGIN`: comma/whitespace separated, trailing `/`
/// dropped, empties skipped, duplicates removed (first wins).
pub fn parse(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for o in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let o = o.trim().trim_end_matches('/');
        if o.is_empty() || out.iter().any(|x| x.eq_ignore_ascii_case(o)) {
            continue;
        }
        out.push(o.to_string());
    }
    out
}

/// `host[:port]` of an origin like `https://a.b:8443`.
fn authority(origin: &str) -> &str {
    let rest = origin.split_once("://").map(|(_, r)| r).unwrap_or(origin);
    rest.split('/').next().unwrap_or(rest)
}

/// Whether a `Host` header value names this origin (case-insensitive; the
/// scheme's default port may be spelled out or not).
fn host_matches(origin: &str, host: &str) -> bool {
    let auth = authority(origin);
    if auth.eq_ignore_ascii_case(host) {
        return true;
    }
    let default_port = if origin.starts_with("https://") {
        ":443"
    } else if origin.starts_with("http://") {
        ":80"
    } else {
        return false;
    };
    host.len() > default_port.len()
        && host[host.len() - default_port.len()..].eq_ignore_ascii_case(default_port)
        && auth.eq_ignore_ascii_case(&host[..host.len() - default_port.len()])
}

/// The origin to serve a request with this `Host` on: the listed one it names,
/// else the first; `None` when no origin is configured (local dev).
pub fn pick<'a>(origins: &'a [String], host: Option<&str>) -> Option<&'a str> {
    let host = host.map(str::trim).filter(|h| !h.is_empty());
    if let Some(h) = host {
        if let Some(o) = origins.iter().find(|o| host_matches(o, h)) {
            return Some(o);
        }
    }
    origins.first().map(String::as_str)
}

/// Whether a browser `Origin` header is one of ours.
pub fn allowed(origins: &[String], origin: &str) -> bool {
    origins.iter().any(|o| o.eq_ignore_ascii_case(origin))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two() -> Vec<String> {
        parse("https://remote.siriusfrk.ru, https://remote.siriusfrk.me/")
    }

    #[test]
    fn parse_single_and_list() {
        assert_eq!(parse("https://a.b"), vec!["https://a.b"]);
        assert_eq!(parse("https://a.b/"), vec!["https://a.b"]);
        assert_eq!(
            two(),
            vec!["https://remote.siriusfrk.ru", "https://remote.siriusfrk.me"]
        );
        assert_eq!(
            parse(" https://a.b ,,https://A.b, https://c.d "),
            vec!["https://a.b", "https://c.d"]
        );
        assert!(parse("").is_empty());
        assert!(parse(" , ").is_empty());
    }

    #[test]
    fn pick_by_host() {
        let o = two();
        assert_eq!(
            pick(&o, Some("remote.siriusfrk.me")),
            Some("https://remote.siriusfrk.me")
        );
        assert_eq!(
            pick(&o, Some("Remote.SiriusFrk.ME")),
            Some("https://remote.siriusfrk.me")
        );
        assert_eq!(
            pick(&o, Some("remote.siriusfrk.me:443")),
            Some("https://remote.siriusfrk.me")
        );
        assert_eq!(
            pick(&o, Some("remote.siriusfrk.ru")),
            Some("https://remote.siriusfrk.ru")
        );
    }

    #[test]
    fn pick_falls_back_to_first() {
        let o = two();
        assert_eq!(pick(&o, None), Some("https://remote.siriusfrk.ru"));
        assert_eq!(pick(&o, Some("")), Some("https://remote.siriusfrk.ru"));
        assert_eq!(
            pick(&o, Some("evil.example")),
            Some("https://remote.siriusfrk.ru")
        );
        // A wrong port is a different origin.
        assert_eq!(
            pick(&o, Some("remote.siriusfrk.me:8443")),
            Some("https://remote.siriusfrk.ru")
        );
        assert_eq!(pick(&[], Some("remote.siriusfrk.me")), None);
    }

    #[test]
    fn pick_with_explicit_port() {
        let o = parse("http://localhost:8080,https://relay.example");
        assert_eq!(
            pick(&o, Some("localhost:8080")),
            Some("http://localhost:8080")
        );
        assert_eq!(pick(&o, Some("localhost")), Some("http://localhost:8080"));
        assert_eq!(
            pick(&o, Some("relay.example")),
            Some("https://relay.example")
        );
    }

    #[test]
    fn allowed_any_listed() {
        let o = two();
        assert!(allowed(&o, "https://remote.siriusfrk.ru"));
        assert!(allowed(&o, "https://remote.siriusfrk.me"));
        assert!(!allowed(&o, "http://remote.siriusfrk.me"));
        assert!(!allowed(&o, "https://evil.example"));
        assert!(!allowed(&o, "null"));
    }
}
