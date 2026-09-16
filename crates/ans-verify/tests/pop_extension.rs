#![cfg(feature = "scitt")]
#![allow(clippy::unwrap_used)]

use std::error::Error as _;

use ans_verify::{PopError, PopErrorKind, ReplayCache};

struct ExternalReplayBackend;

#[async_trait::async_trait]
impl ReplayCache for ExternalReplayBackend {
    async fn check_and_store(&self, _key: &str, _exp_unix: i64) -> Result<bool, PopError> {
        Err(PopError::with_source(
            PopErrorKind::ReplayCacheUnavailable,
            "external replay service timed out",
            std::io::Error::from(std::io::ErrorKind::TimedOut),
        ))
    }
}

#[tokio::test]
async fn external_backend_can_report_a_failure_with_its_original_cause() {
    let error = ExternalReplayBackend
        .check_and_store("proof-key", i64::MAX)
        .await
        .unwrap_err();
    assert_eq!(error.kind, PopErrorKind::ReplayCacheUnavailable);
    let cause = error
        .source()
        .unwrap()
        .downcast_ref::<std::io::Error>()
        .unwrap();
    assert_eq!(cause.kind(), std::io::ErrorKind::TimedOut);
}
