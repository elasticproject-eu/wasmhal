// Error types for the ELASTIC TEE HAL

use thiserror::Error;

/// Result type alias for HAL operations
pub type HalResult<T> = Result<T, HalError>;

/// Main error type for HAL operations
#[derive(Error, Debug, Clone)]
pub enum HalError {
    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    #[error("TEE initialization failed: {0}")]
    TeeInitializationFailed(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),

    #[error("Network operation failed: {0}")]
    NetworkError(String),

    #[error("Storage operation failed: {0}")]
    StorageError(String),

    #[error("GPU operation failed: {0}")]
    GpuError(String),

    #[error("Resource allocation failed: {0}")]
    ResourceError(String),

    #[error("Event handling failed: {0}")]
    EventError(String),

    #[error("Communication failed: {0}")]
    CommunicationError(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Operation not supported: {0}")]
    NotSupported(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Operation timeout: {0}")]
    Timeout(String),

    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for HalError {
    fn from(err: std::io::Error) -> Self {
        HalError::Internal(format!("IO error: {}", err))
    }
}

impl From<serde_json::Error> for HalError {
    fn from(err: serde_json::Error) -> Self {
        HalError::Internal(format!("Serialization error: {}", err))
    }
}

impl From<ring::error::Unspecified> for HalError {
    fn from(_: ring::error::Unspecified) -> Self {
        HalError::CryptographicError("Ring cryptographic operation failed".to_string())
    }
}

/// Error codes for WASI compatibility
#[repr(u32)]
pub enum HalErrorCode {
    Success = 0,
    PlatformNotSupported = 1,
    TeeInitializationFailed = 2,
    CryptographicError = 3,
    NetworkError = 4,
    StorageError = 5,
    GpuError = 6,
    ResourceError = 7,
    EventError = 8,
    CommunicationError = 9,
    InvalidParameter = 10,
    NotSupported = 11,
    PermissionDenied = 12,
    NotFound = 13,
    Timeout = 14,
    AttestationFailed = 15,
    Internal = 16,
}

impl From<HalError> for HalErrorCode {
    fn from(error: HalError) -> Self {
        match error {
            HalError::PlatformNotSupported(_) => HalErrorCode::PlatformNotSupported,
            HalError::TeeInitializationFailed(_) => HalErrorCode::TeeInitializationFailed,
            HalError::CryptographicError(_) => HalErrorCode::CryptographicError,
            HalError::NetworkError(_) => HalErrorCode::NetworkError,
            HalError::StorageError(_) => HalErrorCode::StorageError,
            HalError::GpuError(_) => HalErrorCode::GpuError,
            HalError::ResourceError(_) => HalErrorCode::ResourceError,
            HalError::EventError(_) => HalErrorCode::EventError,
            HalError::CommunicationError(_) => HalErrorCode::CommunicationError,
            HalError::InvalidParameter(_) => HalErrorCode::InvalidParameter,
            HalError::NotSupported(_) => HalErrorCode::NotSupported,
            HalError::PermissionDenied(_) => HalErrorCode::PermissionDenied,
            HalError::NotFound(_) => HalErrorCode::NotFound,
            HalError::Timeout(_) => HalErrorCode::Timeout,
            HalError::AttestationFailed(_) => HalErrorCode::AttestationFailed,
            HalError::Internal(_) => HalErrorCode::Internal,
        }
    }
}
