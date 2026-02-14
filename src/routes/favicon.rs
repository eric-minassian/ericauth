use axum::{
    http::header::{CACHE_CONTROL, CONTENT_TYPE},
    response::IntoResponse,
};

const FAVICON_SVG: &str = r##"<svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M6 10C6 6 10 4 16 4C22 4 26 7 26 11C26 14 24 16 20 16"
    stroke="#171717"
    stroke-width="3.5"
    stroke-linecap="round"
    fill="none"
  />
  <path
    d="M12 16C8 16 6 18 6 21C6 25 10 28 16 28C22 28 26 26 26 22"
    stroke="#171717"
    stroke-width="3.5"
    stroke-linecap="round"
    fill="none"
  />
</svg>
"##;

pub async fn handler() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "image/svg+xml"),
            (CACHE_CONTROL, "public, max-age=86400"),
        ],
        FAVICON_SVG,
    )
}
