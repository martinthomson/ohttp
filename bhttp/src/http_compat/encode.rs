use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    rw::{write_len, write_vec},
    ControlData, Error, Field, FieldSection, Mode, Res, StatusCode,
};
use bytes::Bytes;
use futures_core::stream::Stream as FuturesStream;
use http::{HeaderMap, Request, Response};
use http_body::Body as HttpBody;

/// Helper function to build a [`FieldSection`] from HTTP headers
impl TryFrom<&HeaderMap> for FieldSection {
    type Error = Error;

    fn try_from(headers: &HeaderMap) -> Res<FieldSection> {
        let fields = headers
            .iter()
            .map(|(name, value)| {
                Field::new(name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec())
            })
            .collect::<Vec<_>>();

        Ok(FieldSection(fields))
    }
}

impl TryFrom<&FieldSection> for HeaderMap {
    type Error = Error;

    fn try_from(field_section: &FieldSection) -> Res<HeaderMap> {
        let headers = field_section
            .iter()
            .map(|field| {
                Ok((
                    http::header::HeaderName::from_bytes(field.name())
                        .map_err(http::Error::from)?,
                    http::header::HeaderValue::from_bytes(field.value())
                        .map_err(http::Error::from)?,
                ))
            })
            .collect::<Res<HeaderMap<_>>>()?;

        Ok(headers)
    }
}

/// Enum to wrap either an HTTP Request or Response for unified BHTTP encoding
#[derive(Debug)]
enum HttpMessage<T> {
    Request(Request<T>),
    Response(Response<T>),
}

impl<T> HttpMessage<T> {
    /// Generate BHTTP headers field section from the wrapped request or response
    fn bhttp_headers(&self) -> Res<FieldSection> {
        let http_headers = match self {
            Self::Request(req) => req.headers(),
            Self::Response(res) => res.headers(),
        };

        FieldSection::try_from(http_headers)
    }

    /// Generate control data from the wrapped request or response for BHTTP encoding
    fn bhttp_control_data(&self) -> Res<ControlData> {
        match self {
            Self::Request(req) => {
                let method = req.method().as_str().as_bytes().to_vec();
                let uri = req.uri();

                let scheme = uri.scheme_str().unwrap_or("https").as_bytes().to_vec();
                let authority = uri
                    .authority()
                    .map(|a| a.as_str().as_bytes().to_vec())
                    .unwrap_or_default();
                let path = uri
                    .path_and_query()
                    .map(|p| p.as_str().as_bytes().to_vec())
                    .unwrap_or_else(|| b"/".to_vec());

                Ok(ControlData::Request {
                    method,
                    scheme,
                    authority,
                    path,
                })
            }
            Self::Response(res) => {
                let status_code = StatusCode::try_from(res.status().as_u16())
                    .map_err(|_| Error::InvalidStatus)?;
                Ok(ControlData::Response(status_code))
            }
        }
    }

    /// Get a mutable reference to the body of the wrapped request or response
    fn body_mut(&mut self) -> &mut T {
        match self {
            Self::Request(req) => req.body_mut(),
            Self::Response(res) => res.body_mut(),
        }
    }
}

/// This type provides functionality to encode `http::Request`/`http::Response`
/// structures into BHTTP format through asynchronous streaming.
///
/// The encoder works with any type that implements [http_body::Body], allowing
/// for efficient streaming encoding of HTTP data without needing to load the entire
/// message into memory. This struct implements the [futures_core::stream::Stream]
/// trait, producing chunks of BHTTP-encoded binary data. It supports streaming
/// bodies and trailers.
///
/// # Important Notes
///
/// - Currently, we always use **Indeterminate-Length Messages** since we have no
///   way to know the length of the HTTP body in advance.
/// - Due to limitations in the http crate, any Informational Response (1xx) status
///   codes in HTTP responses will be ignored during encoding.
/// - In our support for Indeterminate-Length Binary Encoding, the body is treated
///   as a continuous binary stream, which means HTTP frames might be reorganized
///   or split. Applications should implement their own framing methods and should
///   not assume that Frame encodings from the http crate will remain the same
///   after encoding and decoding.
pub struct BhttpEncoder<T> {
    state: EncodeState,
    message: HttpMessage<T>,
}

/// The internal state of the BHTTP encoder
enum EncodeState {
    /// Initial state, ready to encode control data and headers
    ControlAndHeaders,
    /// Streaming body chunks and collecting trailers
    BodyChunk {
        collected_trailers: Option<HeaderMap>,
    },
    /// All data has been encoded
    Done,
}

impl<T> BhttpEncoder<T> {
    /// Create a new converter for an HTTP request
    ///
    /// # Arguments
    ///
    /// * `request` - The HTTP request to convert to BHTTP format
    pub fn from_request(request: Request<T>) -> Self {
        Self {
            state: EncodeState::ControlAndHeaders,
            message: HttpMessage::Request(request),
        }
    }

    /// Create a new converter for an HTTP response
    ///
    /// # Arguments
    ///
    /// * `response` - The HTTP response to convert to BHTTP format
    pub fn from_response(response: Response<T>) -> Self {
        Self {
            state: EncodeState::ControlAndHeaders,
            message: HttpMessage::Response(response),
        }
    }
}

impl<T> FuturesStream for BhttpEncoder<T>
where
    T: HttpBody<Data = Bytes> + Unpin,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    type Item = Res<Vec<u8>>;

    /// Poll for the next chunk of BHTTP-encoded data
    ///
    /// This method implements the streaming encoding process:
    /// 1. First, it encodes the control data and headers
    /// 2. Then, it streams the body data in chunks
    /// 3. Finally, it handles trailers if present
    ///
    /// For those who needs a [futures::prelude::AsyncRead] or
    /// [futures::stream::IntoAsyncRead], see
    /// [`into_async_read`](futures::stream::TryStreamExt::into_async_read).
    ///
    /// # Arguments
    ///
    /// * `cx` - The task context for polling
    ///
    /// # Returns
    ///
    /// * `Poll::Ready(Some(Ok(Vec<u8>)))` - Next chunk of BHTTP data
    /// * `Poll::Ready(Some(Err(Error)))` - An error occurred during encoding
    /// * `Poll::Ready(None)` - All data has been encoded
    /// * `Poll::Pending` - No data is ready yet, but may be in the future
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match &mut this.state {
            EncodeState::ControlAndHeaders => {
                let mut buf = Vec::new();

                let control_data = this.message.bhttp_control_data()?;

                // 1. Write the framing indicator.
                control_data
                    .framing_indicator(Mode::IndeterminateLength)
                    .write_bhttp(&mut buf)?;

                // 2. Response with with informational code (100 - 199) is not supported so we just skip encoding Informational Response.
                if let Some(code) = control_data.status() {
                    if code.informational() {
                        return Poll::Ready(Some(Err(Error::UnsportedStatusCode(code.code()))));
                    }
                }

                // 3. Write (request / the final response) control data
                control_data.write_bhttp(&mut buf)?;

                // 4. Write headers field section
                let field_section = this.message.bhttp_headers()?;
                field_section.write_bhttp(Mode::IndeterminateLength, &mut buf)?;

                // 5. Change to next state
                this.state = EncodeState::BodyChunk {
                    collected_trailers: None,
                };
                Poll::Ready(Some(Ok(buf)))
            }
            EncodeState::BodyChunk { collected_trailers } => {
                // Poll the body for more data
                let body = this.message.body_mut();
                match Pin::new(body).poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => {
                        match frame.into_data() {
                            Ok(data) => {
                                // Is a data frame
                                let mut chunk_data = Vec::new();
                                write_vec(&data, &mut chunk_data)?;
                                Poll::Ready(Some(Ok(chunk_data)))
                            }
                            Err(frame) => {
                                if let Ok(trailers) = frame.into_trailers() {
                                    // Is a trailers frame
                                    if let Some(current) = collected_trailers {
                                        current.extend(trailers);
                                    } else {
                                        *collected_trailers = Some(trailers);
                                    }
                                    Poll::Pending
                                } else {
                                    // For unknown frame types, report an invalid data error.
                                    this.state = EncodeState::Done;
                                    Poll::Ready(Some(Err(Error::UnknownHttpBodyFrameType)))
                                }
                            }
                        }
                    }
                    Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Error::Io(
                        std::io::Error::new(std::io::ErrorKind::Other, e),
                    )))),
                    Poll::Ready(None) => {
                        // End of body, write zero-length chunk to indicate end, since we always using Mode::IndeterminateLength
                        let mut buf = Vec::new();
                        write_len(0, &mut buf)?;

                        // Then, write the trailer field section with indeterminate length mode
                        let field_section =
                            if let Some(collected_trailers) = collected_trailers.as_ref() {
                                FieldSection::try_from(collected_trailers)?
                            } else {
                                FieldSection(vec![])
                            };
                        field_section.write_bhttp(Mode::IndeterminateLength, &mut buf)?;

                        // Switch to Done state since we have written the trailers
                        this.state = EncodeState::Done;

                        Poll::Ready(Some(Ok(buf)))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
            EncodeState::Done => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::executor::block_on;
    use futures::StreamExt;
    use http::{Request, Response};
    use http_body::Frame;
    use http_body_util::Full;
    use http_body_util::StreamBody;

    #[test]
    fn test_request_to_bhttp_conversion() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/path")
            .header("User-Agent", "test-agent")
            .header("Accept", "application/json")
            .body(Full::new(Bytes::from("test body")))
            .unwrap();

        let stream = BhttpEncoder::from_request(request);
        let future = stream.fold(Vec::new(), |mut acc, item| async move {
            if let Ok(data) = item {
                acc.extend(data);
            }
            acc
        });

        let bhttp_data = block_on(future);

        // Verify that we got some data
        assert!(!bhttp_data.is_empty());

        // The data should be longer than just the body since it includes headers and metadata
        assert!(bhttp_data.len() > 9);
    }

    #[test]
    fn test_response_to_bhttp_conversion() {
        let response = Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .header("Server", "test-server")
            .body(Full::new(Bytes::from("test response body")))
            .unwrap();

        let stream = BhttpEncoder::from_response(response);
        let future = stream.fold(Vec::new(), |mut acc, item| async move {
            if let Ok(data) = item {
                acc.extend(data);
            }
            acc
        });

        let bhttp_data = block_on(future);

        // Verify that we got some data
        assert!(!bhttp_data.is_empty());

        // The data should be longer than just the body since it includes headers and metadata
        assert!(bhttp_data.len() > 18);
    }

    #[test]
    fn test_trailers_conversion() {
        // Create a body with trailers
        let data_frame = Frame::data(Bytes::from("test body"));

        // Create trailers
        let mut trailers = HeaderMap::new();
        trailers.insert("Trailer-Key", "Trailer-Value".parse().unwrap());

        let trailer_frame = Frame::trailers(trailers);

        let body = StreamBody::new(futures::stream::iter([
            Ok::<_, std::convert::Infallible>(data_frame),
            Ok::<_, std::convert::Infallible>(trailer_frame),
        ]));

        let response = Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body(body)
            .unwrap();

        let stream = BhttpEncoder::from_response(response);
        let future = stream.fold(Vec::new(), |mut acc, item| async move {
            if let Ok(data) = item {
                acc.extend(data);
            }
            acc
        });

        let bhttp_data = block_on(future);

        // Verify that we got some data
        assert!(!bhttp_data.is_empty());
    }

    #[test]
    fn test_encode_rfc9292_request_example_indeterminate_length() {
        // Modifyed example from Section 5.1 of RFC 9292 - Indeterminate-Length Binary Encoding of Request
        const REQUEST_EXAMPLE: &[u8] = &[
            0x02, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x09, 0x68, 0x65,
            0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x01, 0x2f, 0x0a, 0x75, 0x73, 0x65, 0x72,
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

        // Create the HTTP request as specified in the RFC
        let request = Request::builder()
            .method("GET")
            .uri("https://hello.txt")
            .header(
                "user-agent",
                "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3",
            )
            .header("host", "www.example.com")
            .header("accept-language", "en, mi")
            .body(Full::new(Bytes::new())) // No body for this request
            .unwrap();

        // Encode the request to BHTTP using our streaming encoder
        let stream = BhttpEncoder::from_request(request);
        let future = stream.fold(Vec::new(), |mut acc, item| async move {
            if let Ok(data) = item {
                acc.extend(data);
            }
            acc
        });

        let bhttp_data = block_on(future);

        compare_encoded_data_with_the_expected_example(&bhttp_data, REQUEST_EXAMPLE);
    }

    fn compare_encoded_data_with_the_expected_example(generated: &[u8], expected: &[u8]) {
        // Compare the encoded data with the expected example
        // BHTTP allows trailing padding, so we need to check if our data matches
        // the expected data, ignoring any trailing zeros in the expected data

        // Find where the actual data ends (ignoring trailing zeros)
        let expected_end = expected
            .iter()
            .rposition(|&x| x != 0)
            .map(|i| i + 1)
            .unwrap_or(0);

        let generated_end = generated
            .iter()
            .rposition(|&x| x != 0)
            .map(|i| i + 1)
            .unwrap_or(0);

        // Check that the first part matches exactly
        assert_eq!(
            hex::encode(&generated[..generated_end]),
            hex::encode(&expected[..expected_end])
        );
    }
}
