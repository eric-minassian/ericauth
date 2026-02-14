/// Build a query string from optional key-value pairs, URL-encoding values.
/// Used for error redirect URLs in form handlers.
pub fn build_oauth_qs(params: &[(&str, &Option<String>)]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for &(key, value) in params {
        if let Some(v) = value {
            parts.push(format!("{}={}", key, urlencoding::encode(v)));
        }
    }
    parts.join("&")
}

/// Build a URL-encoded query string from optional key-value pairs.
/// Uses `form_urlencoded::Serializer` for proper encoding.
/// Used for building OAuth link query strings in page templates.
pub fn build_oauth_link_query(params: &[(&str, &Option<String>)]) -> String {
    let mut qs = form_urlencoded::Serializer::new(String::new());
    let mut has_params = false;
    for &(key, value) in params {
        if let Some(v) = value {
            qs.append_pair(key, v);
            has_params = true;
        }
    }
    if has_params {
        qs.finish()
    } else {
        String::new()
    }
}
