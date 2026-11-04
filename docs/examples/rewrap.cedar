// Grant migration on every involved logical key. RewrapKey separately checks
// child, old_parent and new_parent, even if both parents are the same key.
permit (
    principal,
    action == KeyRack::Action::"kms:RewrapKey",
    resource
) when {
    resource == KeyRack::Resource::"child-key" ||
    resource == KeyRack::Resource::"old-parent" ||
    resource == KeyRack::Resource::"new-parent"
};
