// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Startup file checks, not proof that a deployment separates process identities.
use crate::core::Error;
use std::path::Path;
use zeroize::Zeroizing;

#[cfg(unix)]
fn validate(metadata: &std::fs::Metadata, worker_uid: u32) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file() || metadata.uid() != worker_uid || metadata.mode() & 0o077 != 0 {
        return Err(Error::Credential);
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn load(path: &Path) -> Result<Zeroizing<String>, Error> {
    use rustix::fs::{open, Mode, OFlags};
    use std::io::Read;

    // Validate the opened descriptor, then read that same descriptor: no
    // check-path/reopen race. Reject final symlinks and avoid hanging on FIFOs.
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| Error::Credential)?;
    let mut file = std::fs::File::from(fd);
    let worker_uid = rustix::process::geteuid().as_raw();
    validate(&file.metadata().map_err(|_| Error::Credential)?, worker_uid)?;
    let mut token = Zeroizing::new(String::new());
    (&mut file)
        .take(4097)
        .read_to_string(&mut token)
        .map_err(|_| Error::Credential)?;
    if token.is_empty() || token.len() > 4096 {
        return Err(Error::Credential);
    }
    validate(&file.metadata().map_err(|_| Error::Credential)?, worker_uid)?;
    Ok(token)
}

#[cfg(not(unix))]
pub(crate) fn load(_path: &Path) -> Result<Zeroizing<String>, Error> {
    // No equivalent ownership/ACL check implemented for this platform yet.
    Err(Error::Credential)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    #[test]
    fn accepts_worker_owned_private_file_and_rejects_foreign_uid() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), "fixture-token").unwrap();
        for mode in [0o600, 0o400] {
            fs::set_permissions(file.path(), fs::Permissions::from_mode(mode)).unwrap();
            // Keep failure output redacted; assert_eq! would print the credential.
            assert!(load(file.path()).unwrap().as_str().eq("fixture-token"));
        }
        // Uses real private-file metadata and a different expected worker UID;
        // no root/chown fixture is needed to exercise the ownership refusal.
        let other_uid = rustix::process::geteuid().as_raw().wrapping_add(1);
        assert_eq!(
            validate(&file.as_file().metadata().unwrap(), other_uid),
            Err(Error::Credential)
        );
    }

    #[test]
    fn rejects_group_world_access_symlinks_and_non_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        fs::write(&path, "fixture-token").unwrap();
        for mode in [0o640, 0o604, 0o620, 0o602, 0o601] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(load(&path), Err(Error::Credential)),
                "mode {mode:o}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(matches!(load(&link), Err(Error::Credential)));
        assert!(matches!(load(directory.path()), Err(Error::Credential)));
        let fifo = directory.path().join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(matches!(load(&fifo), Err(Error::Credential)));
    }

    #[test]
    fn rejects_empty_oversized_and_non_utf8_credentials() {
        let file = tempfile::NamedTempFile::new().unwrap();
        for bytes in [Vec::new(), vec![b'x'; 4097], vec![0xff]] {
            fs::write(file.path(), bytes).unwrap();
            assert!(matches!(load(file.path()), Err(Error::Credential)));
        }
    }
}
