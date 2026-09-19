//! Private, atomic writes for locally persisted inference evidence.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Atomically replace `path` with a newly created owner-private file.
///
/// Writing a unique sibling and renaming it avoids following a symlink at the
/// destination path. On Unix the temporary file is created with mode `0600`;
/// the caller's umask may make it stricter, but never more permissive.
pub fn write_private_file(path: impl AsRef<Path>, contents: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output path must name a file",
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut temporary_name = OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let temporary_path = parent.join(temporary_name);

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);

        let mut file = options.open(&temporary_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary_path, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

/// Build a sidecar path without converting a potentially non-UTF-8 path to a
/// lossy string.
pub fn path_with_suffix(path: impl AsRef<Path>, suffix: &str) -> PathBuf {
    let mut output = path.as_ref().as_os_str().to_os_string();
    output.push(suffix);
    PathBuf::from(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "ephemeralml-private-file-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&directory).expect("create private-file test directory");
        directory
    }

    #[cfg(unix)]
    #[test]
    fn writes_owner_only_and_replaces_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = test_directory();
        let path = directory.join("receipt.json");
        fs::write(&path, b"old").expect("write existing file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("set permissive fixture mode");

        write_private_file(&path, b"new evidence").expect("write private evidence");

        assert_eq!(fs::read(&path).unwrap(), b"new evidence");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(directory).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replaces_destination_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let directory = test_directory();
        let target = directory.join("target");
        let destination = directory.join("receipt.json");
        fs::write(&target, b"do not overwrite").expect("write symlink target");
        symlink(&target, &destination).expect("create destination symlink");

        write_private_file(&destination, b"receipt").expect("write private evidence");

        assert_eq!(fs::read(&target).unwrap(), b"do not overwrite");
        assert_eq!(fs::read(&destination).unwrap(), b"receipt");
        assert!(!fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_dir_all(directory).ok();
    }

    #[test]
    fn appends_sidecar_suffix_without_replacing_extension() {
        assert_eq!(
            path_with_suffix(Path::new("evidence/receipt.json"), ".pubkey"),
            PathBuf::from("evidence/receipt.json.pubkey")
        );
    }
}
