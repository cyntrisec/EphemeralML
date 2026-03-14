//! Buffered SSE streaming support for OpenAI-compatible chat completions.
//!
//! The backend does not support true token-level streaming. Instead, the
//! gateway buffers the full response and then replays it as SSE chunks in
//! the OpenAI streaming format. This lets clients that require `stream=true`
//! (e.g. LangChain, some OpenAI SDKs) work without modification.

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::stream;
use serde::Serialize;
use std::convert::Infallible;

use crate::types::EphemeralMetadata;

/// A single SSE chunk in OpenAI's streaming chat completion format.
#[derive(Serialize, Debug)]
pub struct ChatCompletionChunk {
    pub id: String,
    pub object: &'static str,
    pub created: u64,
    pub model: String,
    pub choices: Vec<StreamChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_ephemeralml")]
    pub metadata: Option<EphemeralMetadata>,
}

#[derive(Serialize, Debug)]
pub struct StreamChoice {
    pub index: u32,
    pub delta: StreamDelta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<&'static str>,
}

#[derive(Serialize, Debug)]
pub struct StreamDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Build an SSE response from a buffered completion.
///
/// Splits the `full_text` into word-level chunks and emits them as SSE events
/// matching the OpenAI streaming format:
///
/// 1. First chunk: `delta.role = "assistant"`, no content
/// 2. Content chunks: `delta.content = "<words>"` (word-level granularity)
/// 3. Final chunk: `finish_reason = "stop"`, empty delta
/// 4. Terminal: `data: [DONE]\n\n`
pub fn build_sse_response(
    id: &str,
    model: &str,
    created: u64,
    full_text: &str,
    metadata: Option<EphemeralMetadata>,
    extra_headers: HeaderMap,
) -> Response {
    let chunks = split_into_chunks(full_text);

    let mut events: Vec<String> = Vec::with_capacity(chunks.len() + 3);

    // First chunk: role announcement.
    let role_chunk = ChatCompletionChunk {
        id: id.to_string(),
        object: "chat.completion.chunk",
        created,
        model: model.to_string(),
        choices: vec![StreamChoice {
            index: 0,
            delta: StreamDelta {
                role: Some("assistant"),
                content: None,
            },
            finish_reason: None,
        }],
        metadata: None,
    };
    events.push(format_sse_event(&role_chunk));

    // Content chunks: one per word group.
    for (i, chunk_text) in chunks.iter().enumerate() {
        let is_last_content = i == chunks.len() - 1;
        let content_chunk = ChatCompletionChunk {
            id: id.to_string(),
            object: "chat.completion.chunk",
            created,
            model: model.to_string(),
            choices: vec![StreamChoice {
                index: 0,
                delta: StreamDelta {
                    role: None,
                    content: Some(chunk_text.clone()),
                },
                finish_reason: None,
            }],
            // Include metadata on the last content chunk so clients can capture it.
            metadata: if is_last_content {
                metadata.clone()
            } else {
                None
            },
        };
        events.push(format_sse_event(&content_chunk));
    }

    // If text was empty, emit a single empty-content chunk.
    if chunks.is_empty() {
        let empty_chunk = ChatCompletionChunk {
            id: id.to_string(),
            object: "chat.completion.chunk",
            created,
            model: model.to_string(),
            choices: vec![StreamChoice {
                index: 0,
                delta: StreamDelta {
                    role: None,
                    content: Some(String::new()),
                },
                finish_reason: None,
            }],
            metadata: metadata.clone(),
        };
        events.push(format_sse_event(&empty_chunk));
    }

    // Final chunk: finish_reason = "stop", empty delta.
    let stop_chunk = ChatCompletionChunk {
        id: id.to_string(),
        object: "chat.completion.chunk",
        created,
        model: model.to_string(),
        choices: vec![StreamChoice {
            index: 0,
            delta: StreamDelta {
                role: None,
                content: None,
            },
            finish_reason: Some("stop"),
        }],
        metadata: None,
    };
    events.push(format_sse_event(&stop_chunk));

    // Terminal [DONE] marker.
    events.push("data: [DONE]\n\n".to_string());

    // Build an SSE body from the collected events.
    let body_stream = stream::iter(events.into_iter().map(Ok::<_, Infallible>));
    let body = axum::body::Body::from_stream(body_stream);

    let mut headers = extra_headers;
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-cache"));
    headers.insert("connection", HeaderValue::from_static("keep-alive"));

    (StatusCode::OK, headers, body).into_response()
}

/// Format a chunk as an SSE `data:` line.
fn format_sse_event(chunk: &ChatCompletionChunk) -> String {
    // serde_json::to_string should not fail on these types.
    match serde_json::to_string(chunk) {
        Ok(json) => format!("data: {json}\n\n"),
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize SSE chunk");
            "data: {\"error\":\"serialization_error\"}\n\n".to_string()
        }
    }
}

/// Split text into word-level chunks suitable for SSE delivery.
///
/// Groups words into chunks of approximately 3-5 words each, preserving
/// whitespace between words. This provides a natural reading cadence for
/// streaming UIs.
fn split_into_chunks(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }

    let words: Vec<&str> = text.split_inclusive(char::is_whitespace).collect();
    if words.is_empty() {
        return vec![text.to_string()];
    }

    let chunk_size = 3; // words per SSE chunk
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut count = 0;

    for word in words {
        current.push_str(word);
        count += 1;
        if count >= chunk_size {
            chunks.push(current.clone());
            current.clear();
            count = 0;
        }
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_empty_text() {
        let chunks = split_into_chunks("");
        assert!(chunks.is_empty());
    }

    #[test]
    fn split_single_word() {
        let chunks = split_into_chunks("hello");
        assert_eq!(chunks, vec!["hello"]);
    }

    #[test]
    fn split_multiple_words() {
        let chunks = split_into_chunks("the quick brown fox jumps over the lazy dog");
        // 9 words, chunk_size=3 -> 3 chunks
        assert_eq!(chunks.len(), 3);
        // Reassembled text should match original.
        let reassembled: String = chunks.concat();
        assert_eq!(reassembled, "the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn sse_event_format() {
        let chunk = ChatCompletionChunk {
            id: "chatcmpl-123".into(),
            object: "chat.completion.chunk",
            created: 1700000000,
            model: "stage-0".into(),
            choices: vec![StreamChoice {
                index: 0,
                delta: StreamDelta {
                    role: Some("assistant"),
                    content: None,
                },
                finish_reason: None,
            }],
            metadata: None,
        };
        let event = format_sse_event(&chunk);
        assert!(event.starts_with("data: "));
        assert!(event.ends_with("\n\n"));
        let json_str = event.strip_prefix("data: ").unwrap().trim();
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed["object"], "chat.completion.chunk");
        assert_eq!(parsed["choices"][0]["delta"]["role"], "assistant");
    }

    #[test]
    fn sse_event_content_chunk() {
        let chunk = ChatCompletionChunk {
            id: "chatcmpl-123".into(),
            object: "chat.completion.chunk",
            created: 1700000000,
            model: "stage-0".into(),
            choices: vec![StreamChoice {
                index: 0,
                delta: StreamDelta {
                    role: None,
                    content: Some("Hello world".into()),
                },
                finish_reason: None,
            }],
            metadata: None,
        };
        let event = format_sse_event(&chunk);
        let json_str = event.strip_prefix("data: ").unwrap().trim();
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed["choices"][0]["delta"]["content"], "Hello world");
        assert!(parsed["choices"][0]["delta"].get("role").is_none());
    }

    #[test]
    fn sse_event_stop_chunk() {
        let chunk = ChatCompletionChunk {
            id: "chatcmpl-123".into(),
            object: "chat.completion.chunk",
            created: 1700000000,
            model: "stage-0".into(),
            choices: vec![StreamChoice {
                index: 0,
                delta: StreamDelta {
                    role: None,
                    content: None,
                },
                finish_reason: Some("stop"),
            }],
            metadata: None,
        };
        let event = format_sse_event(&chunk);
        let json_str = event.strip_prefix("data: ").unwrap().trim();
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn reassembled_text_preserves_whitespace() {
        let text = "Hello, world! This is a test of the streaming system.";
        let chunks = split_into_chunks(text);
        let reassembled: String = chunks.concat();
        assert_eq!(reassembled, text);
    }
}
