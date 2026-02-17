//! Compliance evidence bundle generation and verification for EphemeralML.
//!
//! This crate provides:
//! - Evidence collection and bundling (`evidence`)
//! - Policy evaluation against compliance profiles (`policy`)
//! - Control mapping for regulatory frameworks (`controls`)
//! - Signed bundle export (`export`)

pub mod controls;
pub mod error;
pub mod evidence;
pub mod export;
pub mod policy;

pub use error::{ComplianceError, ComplianceResult};
