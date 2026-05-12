//! Trait boundary for enclave egress helpers.
//!
//! Production implementations live outside `common`: the enclave will speak
//! this protocol over vsock, while tests can use an in-memory mock.

use async_trait::async_trait;

use crate::egress_protocol::{
    EgressError, KmsDecryptRequest, S3PutObjectRequest, S3PutObjectResponse,
};

#[async_trait]
pub trait EgressClient: Send + Sync {
    async fn kms_decrypt(&self, req: KmsDecryptRequest) -> Result<Vec<u8>, EgressError>;

    async fn s3_put_object(
        &self,
        req: S3PutObjectRequest,
    ) -> Result<S3PutObjectResponse, EgressError>;
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::*;

    #[derive(Clone, Default)]
    pub struct MockEgressClient {
        pub kms_plaintext: Arc<Mutex<Vec<u8>>>,
        pub kms_requests: Arc<Mutex<Vec<KmsDecryptRequest>>>,
        pub s3_requests: Arc<Mutex<Vec<S3PutObjectRequest>>>,
    }

    impl MockEgressClient {
        pub fn new(kms_plaintext: Vec<u8>) -> Self {
            Self {
                kms_plaintext: Arc::new(Mutex::new(kms_plaintext)),
                kms_requests: Arc::new(Mutex::new(Vec::new())),
                s3_requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl EgressClient for MockEgressClient {
        async fn kms_decrypt(&self, req: KmsDecryptRequest) -> Result<Vec<u8>, EgressError> {
            self.kms_requests.lock().unwrap().push(req);
            Ok(self.kms_plaintext.lock().unwrap().clone())
        }

        async fn s3_put_object(
            &self,
            req: S3PutObjectRequest,
        ) -> Result<S3PutObjectResponse, EgressError> {
            self.s3_requests.lock().unwrap().push(req);
            Ok(S3PutObjectResponse {
                etag: "\"mock-etag\"".to_string(),
                version_id: Some("mock-version".to_string()),
            })
        }
    }
}
