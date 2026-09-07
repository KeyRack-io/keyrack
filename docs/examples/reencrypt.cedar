// Replace these exact resource IDs with the selected source/destination LIDs.
// This example grants only A -> B, not B -> A or standalone plaintext access.
permit (
    principal == KeyRack::Principal::"keyrack:system",
    action == KeyRack::Action::"kms:ReEncryptFrom",
    resource == KeyRack::Resource::"source-key"
);
permit (
    principal == KeyRack::Principal::"keyrack:system",
    action == KeyRack::Action::"kms:ReEncryptTo",
    resource == KeyRack::Resource::"destination-key"
);
