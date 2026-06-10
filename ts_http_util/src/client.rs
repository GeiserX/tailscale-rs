use std::sync::Arc;

use http::{HeaderName, HeaderValue, Request, Response, header::USER_AGENT};
use hyper::body::{Body, Incoming};

use crate::Error;

/// Default `User-Agent` sent on [`ClientExt`] requests.
///
/// RFC 8555 §6.1 *requires* ACME clients to send a `User-Agent`, and real ACME servers
/// (Boulder/Let's Encrypt, Pebble ≥ 2.10) reject requests without one. No current caller passes
/// its own `User-Agent`; if one ever does, it is appended alongside this default.
const DEFAULT_USER_AGENT: &str = concat!("tailscale-rs/", env!("CARGO_PKG_VERSION"));

/// Build the RFC 7230 §5.3.1 *origin-form* request target (`/path?query`) for a direct request.
///
/// These clients connect straight to the origin server (not through a forward proxy), so the
/// request line must carry only the absolute path and query — never the absolute-form
/// `scheme://host/path`. Passing the full URL makes hyper emit `POST https://host/path HTTP/1.1`,
/// which servers that reconstruct the effective request URI from `Host` + request-target (e.g. an
/// ACME server validating the JWS `url` field) see as a doubled URL, rejecting every request.
fn origin_form_target(url: &url::Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_owned(),
    }
}

/// An HTTP client that can asynchronously send requests and receive responses.
///
/// This trait is HTTP version agnostic; it can be implemented for any version of HTTP.
/// Version-specific features, such as connecting to a server or the HTTP/1.1 protocol upgrade
/// mechanism, must be implemented individually for concrete implementations in addition to the
/// `send` method.
pub trait Client<B>
where
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    /// Sends the given HTTP [`Request`] to the connected server and returns the [`Response`].
    ///
    /// Note that the [`Response`] body of [`Incoming`] means the body must be collected separately
    /// from the [`Response`] status and headers; this allows the status/headers to be checked
    /// before the full body has arrived.
    fn send(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send;
}

/// Extension trait adding specific HTTP method functions (GET, POST, etc.) on top of the base
/// [`Client`] trait.
pub trait ClientExt<B>: Client<B>
where
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    /// Sends an HTTP GET request to the connected server and returns the [`Response`].
    ///
    /// By definition, HTTP GET requests do not contain a body. Note that the [`Response`] body of
    /// [`Incoming`] means the body must be collected separately from the [`Response`] status and
    /// headers; this allows the status/headers to be checked before the full body has arrived.
    fn get(
        &self,
        url: &url::Url,
        headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>>
    where
        B: Default,
    {
        let mut req = Request::get(origin_form_target(url));

        if let Some(hdrs) = req.headers_mut() {
            hdrs.append(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
            hdrs.extend(crate::host_header(url));
            hdrs.extend(headers);
        }

        async move {
            let req = req.body(Default::default()).map_err(|e| {
                tracing::error!(error = %e, "constructing request");
                Error::InvalidInput
            })?;

            self.send(req).await
        }
    }

    /// Sends an HTTP POST request to the connected server and returns the [`Response`].
    ///
    /// Note that the [`Response`] body of [`Incoming`] means the body must be collected separately
    /// from the [`Response`] status and headers; this allows the status/headers to be checked
    /// before the full body has arrived.
    fn post(
        &self,
        url: &url::Url,
        headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
        body: B,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> {
        let mut req = Request::post(origin_form_target(url));

        if let Some(hdrs) = req.headers_mut() {
            hdrs.append(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
            hdrs.extend(crate::host_header(url));
            hdrs.extend(headers);
        }

        async move {
            let req = req.body(body).map_err(|e| {
                tracing::error!(error = %e, "constructing request");
                Error::InvalidInput
            })?;

            self.send(req).await
        }
    }

    /// Sends an HTTP **GET request carrying a body** and returns the [`Response`].
    ///
    /// A GET with a request body is unusual, but it is exactly what the upstream Tailnet-Lock sync
    /// RPCs (`/machine/tka/sync/{offer,send}`) do: control routes on the path and reads a JSON body
    /// off a `GET`. This mirrors [`ClientExt::post`] but with the `GET` method, so callers that must
    /// match that wire shape don't have to hand-build a [`Request`] (and reach for the private
    /// origin-form target helper). Same header defaults as `get`/`post` (UA + `Host`).
    fn get_with_body(
        &self,
        url: &url::Url,
        headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
        body: B,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> {
        let mut req = Request::get(origin_form_target(url));

        if let Some(hdrs) = req.headers_mut() {
            hdrs.append(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
            hdrs.extend(crate::host_header(url));
            hdrs.extend(headers);
        }

        async move {
            let req = req.body(body).map_err(|e| {
                tracing::error!(error = %e, "constructing request");
                Error::InvalidInput
            })?;

            self.send(req).await
        }
    }
}

impl<T, B> ClientExt<B> for T
where
    T: Client<B>,
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
}

impl<T, B> Client<B> for Arc<T>
where
    T: Client<B>,
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    fn send(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send {
        self.as_ref().send(req)
    }
}

impl<T, B> Client<B> for &T
where
    T: Client<B>,
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    fn send(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send {
        (**self).send(req)
    }
}

impl<T, B> Client<B> for &mut T
where
    T: Client<B>,
    B: Body + Send + 'static,
    <B as Body>::Data: Send,
    B::Error: Send + Sync + 'static,
{
    fn send(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send {
        (**self).send(req)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        pin::pin,
        rc::Rc,
        task::{Context, Poll, Waker},
    };

    use bytes::Bytes;
    use http_body_util::Empty;

    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn origin_form_target_no_query() {
        assert_eq!(origin_form_target(&url("https://h/dir")), "/dir");
    }

    #[test]
    fn origin_form_target_with_query() {
        assert_eq!(
            origin_form_target(&url("https://h/dir?x=1&y=2")),
            "/dir?x=1&y=2"
        );
    }

    #[test]
    fn origin_form_target_root_path() {
        // No explicit path normalizes to "/".
        assert_eq!(origin_form_target(&url("https://h")), "/");
    }

    #[test]
    fn origin_form_target_excludes_fragment() {
        // The fragment is never part of the request target.
        assert_eq!(origin_form_target(&url("https://h/p#frag")), "/p");
    }

    #[test]
    fn origin_form_target_is_never_absolute_form() {
        // This is the exact regression that was production-DOA against Let's Encrypt: emitting the
        // absolute-form `scheme://host/path` instead of the origin-form `/path`. Guard it for every
        // shape of URL.
        for u in [
            "https://host.example/dir",
            "https://host.example/dir?x=1&y=2",
            "https://host.example",
            "https://host.example/p#frag",
            "https://host.example:14000/path?q=1",
            "http://host.example/",
        ] {
            let parsed = url(u);
            let target = origin_form_target(&parsed);
            assert!(
                target.starts_with('/'),
                "origin-form target must start with '/': {u} -> {target}"
            );
            assert!(
                !target.starts_with("https://") && !target.starts_with("http://"),
                "origin-form target must not be absolute-form: {u} -> {target}"
            );
            assert!(
                !target.contains("host.example"),
                "origin-form target must not contain the host: {u} -> {target}"
            );
        }
    }

    #[test]
    fn default_user_agent_is_crate_versioned_and_nonempty() {
        assert_eq!(
            DEFAULT_USER_AGENT,
            concat!("tailscale-rs/", env!("CARGO_PKG_VERSION"))
        );
        assert!(!DEFAULT_USER_AGENT.is_empty());
        // It must be a valid header value (constructed via from_static at the call site).
        assert_eq!(
            HeaderValue::from_static(DEFAULT_USER_AGENT),
            DEFAULT_USER_AGENT
        );
    }

    /// A [`Client`] that captures the [`Request`] it is asked to send (so a test can inspect the
    /// headers the `ClientExt` default methods built) and resolves immediately with an error — no
    /// network, no need to construct a `Response<Incoming>`.
    struct CapturingClient {
        seen: Rc<RefCell<Option<http::request::Parts>>>,
    }

    impl Client<Empty<Bytes>> for CapturingClient {
        fn send(
            &self,
            req: Request<Empty<Bytes>>,
        ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send {
            *self.seen.borrow_mut() = Some(req.into_parts().0);
            async { Err(Error::Io) }
        }
    }

    /// Poll a future we know resolves on the first poll (the `ClientExt` GET/POST futures only
    /// `.await` a `send` that returns an already-ready future here). Avoids pulling in a tokio
    /// runtime / executor dependency just to drive a synchronous-completing future.
    fn drive_ready<F: Future>(fut: F) -> F::Output {
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("future did not complete on first poll"),
        }
    }

    #[test]
    fn get_appends_default_user_agent_header() {
        let seen = Rc::new(RefCell::new(None));
        let client = CapturingClient { seen: seen.clone() };
        // The capturing client resolves to Err after recording the request; that's expected.
        assert!(drive_ready(client.get(&url("https://h/dir"), std::iter::empty())).is_err());
        let parts = seen.borrow();
        let parts = parts.as_ref().expect("request was sent");
        assert_eq!(
            parts.headers.get(USER_AGENT).unwrap(),
            concat!("tailscale-rs/", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn post_appends_default_user_agent_header() {
        let seen = Rc::new(RefCell::new(None));
        let client = CapturingClient { seen: seen.clone() };
        // The capturing client resolves to Err after recording the request; that's expected.
        assert!(
            drive_ready(client.post(&url("https://h/dir"), std::iter::empty(), Empty::new()))
                .is_err()
        );
        let parts = seen.borrow();
        let parts = parts.as_ref().expect("request was sent");
        assert_eq!(
            parts.headers.get(USER_AGENT).unwrap(),
            concat!("tailscale-rs/", env!("CARGO_PKG_VERSION"))
        );
    }
}
