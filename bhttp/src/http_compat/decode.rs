use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::AsyncRead as FuturesAsyncRead;
use futures::{stream::BoxStream, StreamExt};
use http::{request, response, HeaderMap, Request, Response, Uri};
use http_body::{Body as HttpBody, Frame};
use tokio_util::{compat::FuturesAsyncReadCompatExt as _, io::ReaderStream};

use crate::{
    stream::{AsyncMessage, AsyncReadMessage as _},
    Error, Message, Res,
};

/// An enum representing either an HTTP request parts or response parts
///
/// This is used internally during the decoding process to handle both
/// request and response types uniformly before constructing the final
/// HTTP structures.
#[derive(Debug)]
enum HttpMessageParts {
    /// An HTTP request parts
    Request(request::Parts),
    /// An HTTP response parts
    Response(response::Parts),
}

/// An enum representing either an HTTP request or response
///
/// This is the final result of the decoding process, containing either
/// a fully constructed HTTP request or response with a streaming body.
pub enum HttpMessage<R> {
    /// An HTTP request with a streaming BHTTP body
    Request(Request<BhttpBody<R>>),
    /// An HTTP response with a streaming BHTTP body
    Response(Response<BhttpBody<R>>),
}

/// A body type that wraps an [`futures::AsyncRead`] and progressively decodes BHTTP body data
///
/// This struct implements the [`http_body::Body`] trait, providing a streaming
/// interface for reading the body data from a BHTTP message. It handles both
/// regular body data and trailers.
pub struct BhttpBody<R> {
    stream: BoxStream<'static, Result<Frame<Bytes>, Error>>,
    _phantom: std::marker::PhantomData<R>,
}

impl<R: FuturesAsyncRead + Unpin + std::marker::Send + 'static> BhttpBody<R> {
    /// Create a new BHTTP body decoder
    ///
    /// # Arguments
    ///
    /// * `async_message` - The async message reader to decode body data from
    pub fn new(mut async_message: AsyncMessage<R>) -> Self {
        let stream = async_stream::try_stream! {
            let body = async_message.body()?;
            let body = body.compat();
            let mut stream = ReaderStream::new(body);

            // Read body data progressively
            while let Some(frame_data) = stream.next().await {
                yield Frame::data(frame_data?);
            }

            // Read trailer data
            let trailers = async_message.trailer().await?;
            let trailers = HeaderMap::try_from(&trailers)?;
            yield Frame::trailers(trailers);
        };

        Self {
            stream: stream.boxed(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R> HttpBody for BhttpBody<R>
where
    R: FuturesAsyncRead + Unpin + 'static,
{
    type Data = Bytes;
    type Error = Error;

    /// Poll for the next frame of body data
    ///
    /// This method implements the streaming body reading process, returning
    /// either data frames or trailer frames as they become available.
    ///
    /// # Arguments
    ///
    /// * `cx` - The task context for polling
    ///
    /// # Returns
    ///
    /// * `Poll::Ready(Some(Ok(Frame<Bytes>)))` - Next frame of body data or trailers
    /// * `Poll::Ready(Some(Err(Error)))` - An error occurred during decoding
    /// * `Poll::Ready(None)` - All body data has been read
    /// * `Poll::Pending` - No data is ready yet, but may be in the future
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.stream.as_mut().poll_next(cx)
    }
}

/// Asynchronous streaming decoding from BHTTP format to HTTP types.
///
/// This type provides functionality to decode BHTTP format data into
/// `http::Request`/`http::Response` structures through asynchronous streaming.
/// Both **Known-Length Message** and **Indeterminate-Length Messages** are supported.
///
/// This decoder works with any type that implements [`futures::AsyncRead`],
/// making it suitable for various input sources like network streams or files.
///
/// # Important Notes
///
/// - Due to limitations in the http crate, any Informational Response (1xx) status
///   codes in HTTP responses will be ignored during encoding.
/// - In our support for Indeterminate-Length Binary Encoding, the body is treated
///   as a continuous binary stream, which means HTTP frames might be reorganized
///   or split. Applications should implement their own framing methods and should
///   not assume that Frame encodings from the http crate will remain the same
///   after encoding and decoding.
pub struct BhttpDecoder<R> {
    reader: R,
}

impl<R> BhttpDecoder<R> {
    /// Create a new BHTTP decoder
    ///
    /// # Arguments
    ///
    /// * `reader` - The async reader to decode BHTTP data from
    pub fn new(reader: R) -> Self {
        Self { reader }
    }
}

impl<R> BhttpDecoder<R>
where
    R: FuturesAsyncRead + Unpin + Send + 'static,
{
    /// Decode an HTTP message from BHTTP format, returning either a request or response
    ///
    /// This method performs the complete decoding process:
    /// 1. Reads the message header
    /// 2. Determines if it's a request or response
    /// 3. Constructs the appropriate HTTP type with a streaming body
    ///
    /// # Returns
    ///
    /// A decode result which can be convert to either an HTTP request or response with a streaming body,
    /// or an error if decoding fails.
    pub async fn decode_message(self) -> Res<HttpMessage<R>> {
        let mut async_message = Message::async_read(self.reader);

        let header = async_message.header().await?;
        let parts = HttpMessageParts::try_from(header)?;

        match parts {
            HttpMessageParts::Request(parts) => Ok(HttpMessage::Request(Request::from_parts(
                parts,
                BhttpBody::new(async_message),
            ))),
            HttpMessageParts::Response(parts) => Ok(HttpMessage::Response(Response::from_parts(
                parts,
                BhttpBody::new(async_message),
            ))),
        }
    }
}

impl TryFrom<crate::Header> for HttpMessageParts {
    type Error = Error;

    /// Convert a BHTTP header into either HTTP request or response parts
    ///
    /// This method parses the control data and field section from a BHTTP header
    /// and constructs the corresponding HTTP request or response parts.
    ///
    /// # Arguments
    ///
    /// * `header` - The BHTTP header to convert
    ///
    /// # Returns
    ///
    /// Either HTTP request parts or response parts, depending on the control data,
    /// or an error if parsing fails.
    fn try_from(header: crate::Header) -> Res<Self> {
        let control_data = header.control();

        if control_data.is_request() {
            // Build the HTTP request parts
            let mut builder = request::Builder::new();

            // Set method
            if let Some(method) = control_data.method() {
                let method_str = std::str::from_utf8(method)?;
                builder = builder.method(method_str);
            }

            // Convert field section to headers
            let headers = HeaderMap::try_from(&header.fields)?;

            // Set URI
            let uri = {
                let mut uri_builder = Uri::builder();

                if let Some(scheme) = control_data.scheme() {
                    uri_builder = uri_builder.scheme(scheme);
                }

                // Handle authority field
                match control_data.authority() {
                    Some(authority_bytes) if !authority_bytes.is_empty() => {
                        uri_builder = uri_builder.authority(std::str::from_utf8(authority_bytes)?);
                    }
                    _ => {
                        // The http::Uri does not allow an absent authority when the scheme is present, but
                        // this is permitted in bhttp and report an InvalidUri(InvalidFormat) error. To
                        // reconcile this difference, we will attempt to retrieve the authority from the
                        // request headers.
                        if control_data.scheme().is_some() {
                            if let Some(host_value) = headers.get("host") {
                                uri_builder = uri_builder.authority(host_value.to_str()?);
                            }
                        }
                    }
                }

                if let Some(path) = control_data.path() {
                    uri_builder = uri_builder.path_and_query(std::str::from_utf8(path)?);
                }

                uri_builder.build()?
            };
            builder = builder.uri(uri);

            // Apply headers to builder
            let mut builder = builder;
            for (name, value) in headers {
                if let Some(name) = name {
                    builder = builder.header(name, value);
                }
            }

            let parts = builder.body(())?.into_parts().0;

            Ok(HttpMessageParts::Request(parts))
        } else {
            // Build the HTTP response parts
            let mut builder = response::Builder::new();

            // Set status code
            if let Some(status) = control_data.status() {
                builder = builder.status(status.code());
            }

            // Convert field section to headers
            let headers = HeaderMap::try_from(&header.fields)?;

            // Apply headers to builder
            let mut builder = builder;
            for (name, value) in headers {
                if let Some(name) = name {
                    builder = builder.header(name, value);
                }
            }

            let parts = builder.body(())?.into_parts().0;

            Ok(HttpMessageParts::Response(parts))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::Cursor;
    use http_body_util::BodyExt;

    #[test]
    fn decode_rfc9292_request_example_known_length() {
        // Example from Section 5.1 of RFC 9292 - Known-Length Binary Encoding of Request
        const REQUEST_EXAMPLE: &[u8] = &[
            0x00, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x00, 0x0a, 0x2f,
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x40, 0x6c, 0x0a, 0x75, 0x73,
            0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x34, 0x63, 0x75, 0x72, 0x6c, 0x2f,
            0x37, 0x2e, 0x31, 0x36, 0x2e, 0x33, 0x20, 0x6c, 0x69, 0x62, 0x63, 0x75, 0x72, 0x6c,
            0x2f, 0x37, 0x2e, 0x31, 0x36, 0x2e, 0x33, 0x20, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53,
            0x4c, 0x2f, 0x30, 0x2e, 0x39, 0x2e, 0x37, 0x6c, 0x20, 0x7a, 0x6c, 0x69, 0x62, 0x2f,
            0x31, 0x2e, 0x32, 0x2e, 0x33, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x0f, 0x77, 0x77, 0x77,
            0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x0f, 0x61,
            0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,
            0x06, 0x65, 0x6e, 0x2c, 0x20, 0x6d, 0x69, 0x00, 0x00,
        ];

        let cursor = Cursor::new(REQUEST_EXAMPLE);
        let decoder = BhttpDecoder::new(cursor);
        let result = block_on(decoder.decode_message()).expect("Failed to decode message");

        match result {
            HttpMessage::Request(request) => {
                // Check method
                assert_eq!(request.method(), http::Method::GET);

                // Check URI
                assert_eq!(request.uri(), "https://www.example.com/hello.txt");

                // Check headers
                let headers = request.headers();
                assert_eq!(
                    headers.get("user-agent").unwrap(),
                    "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"
                );
                assert_eq!(headers.get("host").unwrap(), "www.example.com");
                assert_eq!(headers.get("accept-language").unwrap(), "en, mi");

                // Check body - should be empty
                let body_data = block_on(request.into_body().collect()).unwrap().to_bytes();
                assert!(body_data.is_empty());
            }
            HttpMessage::Response(_) => {
                panic!("Expected a request, but got a response");
            }
        }
    }

    #[test]
    fn decode_rfc9292_request_example_indeterminate_length() {
        // Example from Section 5.1 of RFC 9292 - Indeterminate-Length Binary Encoding of Request
        const REQUEST_EXAMPLE: &[u8] = &[
            0x02, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x00, 0x0a, 0x2f,
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x0a, 0x75, 0x73, 0x65, 0x72,
            0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x34, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e,
            0x31, 0x36, 0x2e, 0x33, 0x20, 0x6c, 0x69, 0x62, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37,
            0x2e, 0x31, 0x36, 0x2e, 0x33, 0x20, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x4c, 0x2f,
            0x30, 0x2e, 0x39, 0x2e, 0x37, 0x6c, 0x20, 0x7a, 0x6c, 0x69, 0x62, 0x2f, 0x31, 0x2e,
            0x32, 0x2e, 0x33, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x0f, 0x61, 0x63, 0x63,
            0x65, 0x70, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x06, 0x65,
            0x6e, 0x2c, 0x20, 0x6d, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let cursor = Cursor::new(REQUEST_EXAMPLE);
        let decoder = BhttpDecoder::new(cursor);
        let result = block_on(decoder.decode_message()).expect("Failed to decode message");

        match result {
            HttpMessage::Request(request) => {
                // Check method
                assert_eq!(request.method(), http::Method::GET);

                // Check URI
                assert_eq!(request.uri(), "https://www.example.com/hello.txt");

                // Check headers
                let headers = request.headers();
                assert_eq!(
                    headers.get("user-agent").unwrap(),
                    "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"
                );
                assert_eq!(headers.get("host").unwrap(), "www.example.com");
                assert_eq!(headers.get("accept-language").unwrap(), "en, mi");

                // Check body - should be empty
                let body_data = block_on(request.into_body().collect()).unwrap().to_bytes();
                assert!(body_data.is_empty());
            }
            HttpMessage::Response(_) => {
                panic!("Expected a request, but got a response");
            }
        }
    }

    #[test]
    fn decode_rfc9292_response_example_inculding_informational_responses() {
        // Example from Section 5.2 of RFC 9292 - Response including Informational Responses
        const RESPONSE_EXAMPLE: &[u8] = &[
            0x03, 0x40, 0x66, 0x07, 0x72, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x0a, 0x22, 0x73,
            0x6c, 0x65, 0x65, 0x70, 0x20, 0x31, 0x35, 0x22, 0x00, 0x40, 0x67, 0x04, 0x6c, 0x69,
            0x6e, 0x6b, 0x23, 0x3c, 0x2f, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x2e, 0x63, 0x73, 0x73,
            0x3e, 0x3b, 0x20, 0x72, 0x65, 0x6c, 0x3d, 0x70, 0x72, 0x65, 0x6c, 0x6f, 0x61, 0x64,
            0x3b, 0x20, 0x61, 0x73, 0x3d, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x04, 0x6c, 0x69, 0x6e,
            0x6b, 0x24, 0x3c, 0x2f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x2e, 0x6a, 0x73, 0x3e,
            0x3b, 0x20, 0x72, 0x65, 0x6c, 0x3d, 0x70, 0x72, 0x65, 0x6c, 0x6f, 0x61, 0x64, 0x3b,
            0x20, 0x61, 0x73, 0x3d, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x00, 0x40, 0xc8, 0x04,
            0x64, 0x61, 0x74, 0x65, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x37, 0x20, 0x4a,
            0x75, 0x6c, 0x20, 0x32, 0x30, 0x30, 0x39, 0x20, 0x31, 0x32, 0x3a, 0x32, 0x38, 0x3a,
            0x35, 0x33, 0x20, 0x47, 0x4d, 0x54, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x06,
            0x41, 0x70, 0x61, 0x63, 0x68, 0x65, 0x0d, 0x6c, 0x61, 0x73, 0x74, 0x2d, 0x6d, 0x6f,
            0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x1d, 0x57, 0x65, 0x64, 0x2c, 0x20, 0x32, 0x32,
            0x20, 0x4a, 0x75, 0x6c, 0x20, 0x32, 0x30, 0x30, 0x39, 0x20, 0x31, 0x39, 0x3a, 0x31,
            0x35, 0x3a, 0x35, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x04, 0x65, 0x74, 0x61, 0x67, 0x14,
            0x22, 0x33, 0x34, 0x61, 0x61, 0x33, 0x38, 0x37, 0x2d, 0x64, 0x2d, 0x31, 0x35, 0x36,
            0x38, 0x65, 0x62, 0x30, 0x30, 0x22, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
            0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x05, 0x62, 0x79, 0x74, 0x65, 0x73, 0x0e, 0x63,
            0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x02,
            0x35, 0x31, 0x04, 0x76, 0x61, 0x72, 0x79, 0x0f, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74,
            0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x0c, 0x63, 0x6f, 0x6e, 0x74,
            0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x0a, 0x74, 0x65, 0x78, 0x74, 0x2f,
            0x70, 0x6c, 0x61, 0x69, 0x6e, 0x00, 0x33, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
            0x6f, 0x72, 0x6c, 0x64, 0x21, 0x20, 0x4d, 0x79, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65,
            0x6e, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x73, 0x20, 0x61, 0x20,
            0x74, 0x72, 0x61, 0x69, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x52, 0x4c, 0x46, 0x2e,
            0x0d, 0x0a, 0x00, 0x00,
        ];

        let cursor = Cursor::new(RESPONSE_EXAMPLE);
        let decoder = BhttpDecoder::new(cursor);
        let result = block_on(decoder.decode_message()).expect("Failed to decode message");

        match result {
            HttpMessage::Response(response) => {
                // Check status
                assert_eq!(response.status(), http::StatusCode::OK);

                // Check headers
                let headers = response.headers();
                assert_eq!(headers.len(), 8); // Note that informational status codes is dropped during decoding
                assert_eq!(
                    headers.get("date").unwrap(),
                    "Mon, 27 Jul 2009 12:28:53 GMT"
                );
                assert_eq!(headers.get("server").unwrap(), "Apache");
                assert_eq!(
                    headers.get("last-modified").unwrap(),
                    "Wed, 22 Jul 2009 19:15:56 GMT"
                );
                assert_eq!(headers.get("etag").unwrap(), "\"34aa387-d-1568eb00\"");
                assert_eq!(headers.get("accept-ranges").unwrap(), "bytes");
                assert_eq!(headers.get("content-length").unwrap(), "51");
                assert_eq!(headers.get("vary").unwrap(), "Accept-Encoding");
                assert_eq!(headers.get("content-type").unwrap(), "text/plain");

                // Check body
                let body_data = block_on(response.into_body().collect()).unwrap().to_bytes();
                assert_eq!(
                    std::str::from_utf8(&body_data).unwrap(),
                    "Hello World! My content includes a trailing CRLF.\r\n"
                );
            }
            HttpMessage::Request(_) => {
                panic!("Expected a response, but got a request");
            }
        }
    }

    #[test]
    fn decode_rfc9292_response_example_known_length_with_trailer() {
        // Example from Section 5.2 of RFC 9292 - Known-Length Encoding of Response
        const RESPONSE_EXAMPLE: &[u8] = &[
            0x01, 0x40, 0xc8, 0x00, 0x1d, 0x54, 0x68, 0x69, 0x73, 0x20, 0x63, 0x6f, 0x6e, 0x74,
            0x65, 0x6e, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x43,
            0x52, 0x4c, 0x46, 0x2e, 0x0d, 0x0a, 0x0d, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x65,
            0x72, 0x04, 0x74, 0x65, 0x78, 0x74,
        ];

        let cursor = Cursor::new(RESPONSE_EXAMPLE);
        let decoder = BhttpDecoder::new(cursor);
        let result = block_on(decoder.decode_message()).expect("Failed to decode message");

        match result {
            HttpMessage::Response(response) => {
                // Check status
                assert_eq!(response.status(), http::StatusCode::OK);

                // Check headers
                let headers = response.headers();
                assert_eq!(headers.len(), 0);

                // Read all body
                let collected = block_on(response.into_body().collect()).unwrap();

                // Check trailers
                let trailers = collected.trailers();
                assert!(trailers.is_some());
                let trailers = trailers.unwrap();
                assert_eq!(trailers.len(), 1);
                assert_eq!(trailers.get("trailer").unwrap(), "text");

                // Check body
                let body_data = collected.to_bytes();
                assert_eq!(
                    std::str::from_utf8(&body_data).unwrap(),
                    "This content contains CRLF.\r\n"
                );
            }
            HttpMessage::Request(_) => {
                panic!("Expected a response, but got a request");
            }
        }
    }
}
