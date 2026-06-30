"""Unit tests for the Wazuh deployer (filesystem-based, no live Wazuh)."""

from deployer.wazuh_deployer import (
    backup_rules,
    deploy_rules,
    deploy_with_rollback,
    health_check,
    restore_backup,
)


def _make_view(tmp_path, view="by_tactic", files=None):
    """Create a fake source rules dir: tmp_path/rules/<view>/*.xml."""
    files = files or {"execution.xml": "<group>new-exec</group>", "impact.xml": "<group>new-impact</group>"}
    src = tmp_path / "rules" / view
    src.mkdir(parents=True)
    for name, content in files.items():
        (src / name).write_text(content)
    return src


def _make_dest(tmp_path, files=None):
    dest = tmp_path / "ossec_rules"
    dest.mkdir(parents=True)
    if files:
        for name, content in files.items():
            (dest / name).write_text(content)
    return dest


def test_backup_rules_copies_existing_xml(tmp_path):
    dest = _make_dest(tmp_path, {"old.xml": "<group>old</group>"})
    backup = backup_rules(dest, backup_dir=tmp_path / "backups")
    assert backup is not None
    assert backup.exists()
    assert (backup / "old.xml").read_text() == "<group>old</group>"


def test_backup_rules_returns_none_when_empty(tmp_path):
    dest = _make_dest(tmp_path)  # no xml files
    assert backup_rules(dest, backup_dir=tmp_path / "backups") is None


def test_backup_rules_returns_none_when_missing(tmp_path):
    assert backup_rules(tmp_path / "does_not_exist") is None


def test_deploy_rules_copies_and_counts(tmp_path):
    src = _make_view(tmp_path)
    dest = tmp_path / "ossec_rules"  # does not exist yet
    count = deploy_rules(src, dest, view="by_tactic")
    assert count == 2
    assert (dest / "execution.xml").read_text() == "<group>new-exec</group>"
    assert (dest / "impact.xml").exists()


def test_deploy_rules_accepts_parent_dir(tmp_path):
    _make_view(tmp_path, view="by_tactic")
    src_parent = tmp_path / "rules"
    dest = tmp_path / "ossec_rules"
    count = deploy_rules(src_parent, dest, view="by_tactic")
    assert count == 2


def test_deploy_rules_includes_parent_rules(tmp_path):
    """parent_rules.xml in the rules root deploys alongside any view."""
    src = _make_view(tmp_path, view="by_tactic")
    # parent_rules.xml lives in the rules root, beside the per-view dirs.
    (tmp_path / "rules" / "parent_rules.xml").write_text("<group>powershell-parent</group>")
    dest = tmp_path / "ossec_rules"
    count = deploy_rules(src, dest, view="by_tactic")
    assert count == 3  # 2 view files + parent_rules.xml
    assert (dest / "parent_rules.xml").read_text() == "<group>powershell-parent</group>"


def test_restore_backup(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "a.xml").write_text("<group>a</group>")
    (backup / "b.xml").write_text("<group>b</group>")
    dest = tmp_path / "dest"
    restored = restore_backup(backup, dest)
    assert restored == 2
    assert (dest / "a.xml").read_text() == "<group>a</group>"


def test_health_check_default_true():
    assert health_check() is True


def test_health_check_injected():
    assert health_check(lambda: False) is False
    assert health_check(lambda: True) is True


def test_health_check_exception_is_unhealthy():
    def boom():
        raise RuntimeError("manager down")

    assert health_check(boom) is False


def test_deploy_with_rollback_healthy(tmp_path):
    src = _make_view(tmp_path)
    dest = _make_dest(tmp_path, {"execution.xml": "<group>OLD-exec</group>"})

    summary = deploy_with_rollback(
        src,
        dest,
        view="by_tactic",
        check_fn=lambda: True,
        backup_dir=tmp_path / "backups",
    )

    assert summary["healthy"] is True
    assert summary["rolled_back"] is False
    assert summary["deployed"] == 2
    assert summary["backed_up"] is True
    # New rules are present in dest.
    assert (dest / "execution.xml").read_text() == "<group>new-exec</group>"
    assert (dest / "impact.xml").exists()


def test_deploy_with_rollback_unhealthy_restores(tmp_path):
    src = _make_view(tmp_path)
    dest = _make_dest(tmp_path, {"execution.xml": "<group>OLD-exec</group>"})

    summary = deploy_with_rollback(
        src,
        dest,
        view="by_tactic",
        check_fn=lambda: False,
        backup_dir=tmp_path / "backups",
    )

    assert summary["healthy"] is False
    assert summary["rolled_back"] is True
    assert summary["backed_up"] is True
    # Dest is restored to pre-deploy contents: original file back, new-only file gone.
    assert (dest / "execution.xml").read_text() == "<group>OLD-exec</group>"
    assert not (dest / "impact.xml").exists()


def test_deploy_with_rollback_unhealthy_no_backup_keeps_deploy(tmp_path):
    src = _make_view(tmp_path)
    dest = _make_dest(tmp_path)  # empty dest -> no backup possible

    summary = deploy_with_rollback(
        src,
        dest,
        view="by_tactic",
        check_fn=lambda: False,
        backup_dir=tmp_path / "backups",
    )

    assert summary["healthy"] is False
    assert summary["backed_up"] is False
    # Nothing to roll back to, so deployed files remain.
    assert summary["rolled_back"] is False
    assert (dest / "execution.xml").exists()
