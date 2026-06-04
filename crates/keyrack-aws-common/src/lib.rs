use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KmsAction {
    CreateKey,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    GenerateDataKey,
    GenerateDataKeyWithoutPlaintext,
    ReEncrypt,
    GenerateRandom,
    DescribeKey,
    ListKeys,
    EnableKey,
    DisableKey,
    ScheduleKeyDeletion,
    CancelKeyDeletion,
    GetKeyPolicy,
    PutKeyPolicy,
    ListAliases,
    CreateAlias,
    DeleteAlias,
    TagResource,
    UntagResource,
    ListResourceTags,
    GetKeyRotationStatus,
    EnableKeyRotation,
    DisableKeyRotation,
}

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("unknown action: {0}")]
    UnknownAction(String),

    #[error("malformed request: {0}")]
    MalformedRequest(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct KmsErrorResponse {
    #[serde(rename = "__type")]
    pub error_type: String,
    #[serde(rename = "Message")]
    pub message: String,
}

/// Parses the AWS `X-Amz-Target` header value (format: `TrentService.ActionName`)
/// into a `KmsAction`.
pub fn parse_action(target_header: &str) -> Result<KmsAction, KmsError> {
    let action_name = target_header.strip_prefix("TrentService.").ok_or_else(|| {
        KmsError::MalformedRequest(format!(
            "expected 'TrentService.' prefix, got: {target_header}"
        ))
    })?;

    match action_name {
        "CreateKey" => Ok(KmsAction::CreateKey),
        "Encrypt" => Ok(KmsAction::Encrypt),
        "Decrypt" => Ok(KmsAction::Decrypt),
        "Sign" => Ok(KmsAction::Sign),
        "Verify" => Ok(KmsAction::Verify),
        "GenerateDataKey" => Ok(KmsAction::GenerateDataKey),
        "GenerateDataKeyWithoutPlaintext" => Ok(KmsAction::GenerateDataKeyWithoutPlaintext),
        "ReEncrypt" => Ok(KmsAction::ReEncrypt),
        "GenerateRandom" => Ok(KmsAction::GenerateRandom),
        "DescribeKey" => Ok(KmsAction::DescribeKey),
        "ListKeys" => Ok(KmsAction::ListKeys),
        "EnableKey" => Ok(KmsAction::EnableKey),
        "DisableKey" => Ok(KmsAction::DisableKey),
        "ScheduleKeyDeletion" => Ok(KmsAction::ScheduleKeyDeletion),
        "CancelKeyDeletion" => Ok(KmsAction::CancelKeyDeletion),
        "GetKeyPolicy" => Ok(KmsAction::GetKeyPolicy),
        "PutKeyPolicy" => Ok(KmsAction::PutKeyPolicy),
        "ListAliases" => Ok(KmsAction::ListAliases),
        "CreateAlias" => Ok(KmsAction::CreateAlias),
        "DeleteAlias" => Ok(KmsAction::DeleteAlias),
        "TagResource" => Ok(KmsAction::TagResource),
        "UntagResource" => Ok(KmsAction::UntagResource),
        "ListResourceTags" => Ok(KmsAction::ListResourceTags),
        "GetKeyRotationStatus" => Ok(KmsAction::GetKeyRotationStatus),
        "EnableKeyRotation" => Ok(KmsAction::EnableKeyRotation),
        "DisableKeyRotation" => Ok(KmsAction::DisableKeyRotation),
        other => Err(KmsError::UnknownAction(other.to_string())),
    }
}

/// Builds an AWS-compatible JSON error response.
pub fn error_response(error_type: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "__type": error_type,
        "Message": message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_actions() {
        assert_eq!(
            parse_action("TrentService.CreateKey").unwrap(),
            KmsAction::CreateKey
        );
        assert_eq!(
            parse_action("TrentService.Decrypt").unwrap(),
            KmsAction::Decrypt
        );
        assert_eq!(
            parse_action("TrentService.GenerateDataKeyWithoutPlaintext").unwrap(),
            KmsAction::GenerateDataKeyWithoutPlaintext
        );
    }

    #[test]
    fn parse_unknown_action() {
        let err = parse_action("TrentService.DoSomethingWeird").unwrap_err();
        assert!(matches!(err, KmsError::UnknownAction(_)));
    }

    #[test]
    fn parse_malformed_header() {
        let err = parse_action("BadPrefix.Encrypt").unwrap_err();
        assert!(matches!(err, KmsError::MalformedRequest(_)));
    }

    #[test]
    fn error_response_format() {
        let resp = error_response("InvalidParameterValue", "Key not found");
        assert_eq!(resp["__type"], "InvalidParameterValue");
        assert_eq!(resp["Message"], "Key not found");
    }
}
