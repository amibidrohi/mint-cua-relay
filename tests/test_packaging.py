from pathlib import Path
import os
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).parents[1]


def test_release_version_is_unified_at_0_3_0():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    package = (ROOT / "src/mint_cua_relay/__init__.py").read_text()
    manifest = (ROOT / "hermes-plugin/plugin.yaml").read_text()
    assert project["project"]["version"] == "0.3.0"
    assert '__version__ = "0.3.0"' in package
    assert 'version: "0.3.0"' in manifest


def test_bootstrap_verifies_signed_checksum_before_archive_checksum():
    script = (ROOT / "install.sh").read_text()
    assert "https://api.github.com/repos/amibidrohi/mint-cua-relay/releases/latest" in script
    assert "https://github.com/amibidrohi/mint-cua-relay/releases/download/" in script
    assert "--proto '=https'" in script
    assert "--tlsv1.2" in script
    assert '"$base/$asset.sha256.sig"' in script
    signature = script.index("pkeyutl -verify")
    checksum = script.index("sha256sum --check")
    assert signature < checksum
    assert "release-public-key.pem" in script


def test_bootstrap_validates_tar_members_and_exact_installer_path():
    script = (ROOT / "install.sh").read_text()
    assert "tar --list" in script
    assert "Unsafe archive member" in script
    assert 'installer="$tmp/source/mint-cua-relay-$version/scripts/install.sh"' in script
    assert "find " not in script


def test_management_command_reports_version_and_status(tmp_path):
    install_root = tmp_path / "mint-cua-relay"
    release = install_root / "releases" / "0.3.0"
    release.mkdir(parents=True)
    (release / "VERSION").write_text("0.3.0\n")
    (install_root / "current").symlink_to(release)
    env = os.environ | {"MINT_CUA_INSTALL_ROOT": str(install_root)}

    version = subprocess.run(
        [ROOT / "scripts/mint-cua", "version"], env=env, text=True,
        capture_output=True, check=True,
    )
    status = subprocess.run(
        [ROOT / "scripts/mint-cua", "status"], env=env, text=True,
        capture_output=True, check=True,
    )
    assert version.stdout.strip() == "mint-cua 0.3.0"
    assert "Installed version: 0.3.0" in status.stdout
    assert f"Current release: {release}" in status.stdout


def test_update_refuses_downgrade_without_explicit_opt_in(tmp_path):
    install_root = tmp_path / "mint-cua-relay"
    release = install_root / "releases" / "0.3.0"
    release.mkdir(parents=True)
    (release / "VERSION").write_text("0.3.0\n")
    (install_root / "current").symlink_to(release)
    env = os.environ | {"MINT_CUA_INSTALL_ROOT": str(install_root)}
    result = subprocess.run(
        [ROOT / "scripts/mint-cua", "update", "0.2.0"], env=env,
        text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "Refusing downgrade" in result.stderr


def test_package_installer_derives_version_and_uses_hashed_lockfile():
    script = (ROOT / "scripts/install.sh").read_text()
    assert 'VERSION="$(python3 - "$ROOT/pyproject.toml"' in script
    assert 'VERSION="0.3.0"' not in script
    assert "--require-hashes" in script
    assert '"$ROOT/requirements.lock"' in script
    assert "--no-deps --no-build-isolation" in script


def test_package_installer_activates_last_and_rolls_back_failed_active_service():
    script = (ROOT / "scripts/install.sh").read_text()
    switch = script.index('mv -Tf "$APP_HOME/.current.new" "$APP_HOME/current"')
    units = script.index('render_unit "$ROOT/packaging/mint-cua-relay.service.in"')
    plugin = script.index('install -m 644 "$ROOT/hermes-plugin/plugin.yaml"')
    assert switch > units and switch > plugin
    assert 'previous_target="$(readlink -f -- "$APP_HOME/current"' in script
    assert "was_active=0" in script
    assert "systemctl --user is-active --quiet mint-cua-relay.service" in script
    assert "systemctl --user restart mint-cua-relay.service" in script
    assert "systemctl --user is-active --quiet mint-cua-relay.service" in script[switch:]
    assert 'ln -s "$previous_target" "$APP_HOME/.current.rollback"' in script
    assert 'mv -Tf "$APP_HOME/.current.rollback" "$APP_HOME/current"' in script
    assert "restore_shared_files" in script
    assert "Rollback failed: previous service is not active" in script


def test_uninstaller_requires_install_marker_and_rejects_home():
    script = (ROOT / "scripts/uninstall.sh").read_text()
    assert '.mint-cua-install-root' in script
    assert 'Refusing unsafe install root' in script
    assert 'realpath' in script


def test_release_lock_has_only_exact_versions_hashes_and_build_backend():
    lock = (ROOT / "requirements.lock").read_text()
    requirements = [line for line in lock.splitlines() if line and not line[0].isspace() and not line.startswith("#")]
    assert requirements
    assert all("==" in line for line in requirements)
    assert "--hash=sha256:" in lock
    assert "setuptools==" in lock
    assert "wheel==" in lock


def test_release_builder_emits_archive_checksum_and_optional_signature(tmp_path):
    key = tmp_path / "test-key.pem"
    public = tmp_path / "test-public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", key], check=True)
    subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-out", public], check=True)
    env = os.environ | {"MINT_CUA_SIGNING_KEY": str(key)}
    result = subprocess.run(
        [ROOT / "scripts/build-release.sh", str(tmp_path)], env=env, text=True,
        capture_output=True, check=True,
    )
    archive = tmp_path / "mint-cua-relay-0.3.0.tar.gz"
    checksum = tmp_path / "mint-cua-relay-0.3.0.tar.gz.sha256"
    signature = tmp_path / "mint-cua-relay-0.3.0.tar.gz.sha256.sig"
    assert archive.exists() and checksum.exists() and signature.exists()
    subprocess.run(["sha256sum", "--check", checksum], cwd=tmp_path, check=True)
    subprocess.run([
        "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", public,
        "-rawin", "-in", checksum, "-sigfile", signature,
    ], check=True)
    with tarfile.open(archive) as release:
        names = set(release.getnames())
    assert "mint-cua-relay-0.3.0/install.sh" in names
    assert "mint-cua-relay-0.3.0/scripts/mint-cua" in names
    assert "mint-cua-relay-0.3.0/release-public-key.pem" in names
    assert "mint-cua-relay-0.3.0/requirements.lock" in names
    assert not any("__pycache__" in name for name in names)
    assert not any(name.endswith(".pyc") for name in names)
    assert not any(".egg-info" in name for name in names)
    assert str(signature) in result.stdout


def test_release_workflow_is_build_only_read_only_and_commit_pinned():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert "scripts/build-release.sh" in workflow
    assert "contents: read" in workflow
    assert "contents: write" not in workflow
    assert "action-gh-release" not in workflow
    assert "MINT_CUA_SIGNING_KEY" not in workflow
    for line in workflow.splitlines():
        if "uses:" in line:
            revision = line.rsplit("@", 1)[-1].split("#", 1)[0].strip()
            assert len(revision) == 40 and all(c in "0123456789abcdef" for c in revision)


def test_readme_documents_pinned_bootstrap_trust_boundary_and_update():
    readme = (ROOT / "README.md").read_text()
    assert "https://raw.githubusercontent.com/amibidrohi/mint-cua-relay/v0.3.0/install.sh" in readme
    assert "/main/install.sh" not in readme
    assert ".sha256.sig" in readme
    assert "trust" in readme.lower() and "bootstrap" in readme.lower()
    assert "mint-cua update" in readme
    assert "mint-cua version" in readme
    assert "mint-cua status" in readme


def test_installer_uses_isolated_venv_private_env_and_safe_template_substitution():
    script = (ROOT / "scripts/install.sh").read_text()
    assert "--system-site-packages" not in script
    assert '"$HOME/.cache/cua-driver"' in script
    assert 'chmod 600 "$CONFIG_HOME/relay.env"' in script
    assert "validate_executable" in script
    assert "CUA_DRIVER_BIN" in script
    assert ".hermes/tools/cua-driver-" in script
    assert "sed " not in script
    assert '"APP_HOME=$APP_HOME"' in script


def test_units_have_private_umask_and_hardening():
    for name in (
        "mint-cua-relay.service.in",
        "mint-cua-cloudflared.service.in",
        "cua-driver-relay.service.in",
    ):
        text = (ROOT / "packaging" / name).read_text()
        assert "UMask=0077" in text
        assert "NoNewPrivileges=true" in text
        assert "ProtectSystem=" in text
        assert "ProtectHome=" in text


def test_manifest_and_docs_include_pinned_service_token_id_and_x11_spoofing_warning():
    manifest = (ROOT / "hermes-plugin/plugin.yaml").read_text()
    readme = (ROOT / "README.md").read_text()
    assert "CF_ACCESS_SERVICE_TOKEN_ID" in manifest
    assert "CF_ACCESS_SERVICE_TOKEN_ID" in readme
    assert "same-user" in readme and "spoof" in readme
    assert "unknown routes" in readme
