use std::path::{Path, PathBuf};

use crate::error::{GitveilError, Result};

pub(crate) fn packaged_sidecar_path(gitveil_binary: &Path, name: &str) -> Result<PathBuf> {
    let bin = gitveil_binary.parent().ok_or_else(|| {
        GitveilError::dependency("Gitveil executable has no installation directory")
    })?;
    let prefix = bin
        .parent()
        .ok_or_else(|| GitveilError::dependency("Gitveil executable has no installation prefix"))?;
    Ok(prefix.join("libexec").join("gitveil").join(name))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::packaged_sidecar_path;

    #[test]
    fn sidecars_are_resolved_from_the_install_prefix() {
        let binary = Path::new("/opt/gitveil/bin/gitveil");
        assert_eq!(
            packaged_sidecar_path(binary, "sops").expect("SOPS path"),
            Path::new("/opt/gitveil/libexec/gitveil/sops")
        );
        assert_eq!(
            packaged_sidecar_path(binary, "age-keygen").expect("age-keygen path"),
            Path::new("/opt/gitveil/libexec/gitveil/age-keygen")
        );
    }
}
