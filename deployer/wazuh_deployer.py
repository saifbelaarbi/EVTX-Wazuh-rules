"""Deploy generated Wazuh rules to a manager with backup, health check, and rollback.

This module orchestrates pushing rule XML files (from ``database/rules/<view>``)
into a Wazuh manager's rules directory (``deploy_path``, e.g.
``/var/ossec/etc/rules/``). It is intentionally filesystem-based so the whole
flow can be unit-tested locally without a live Wazuh manager:

    backup_rules -> deploy_rules -> (restart) -> health_check
                                       |
                                       +--(unhealthy)--> restore_backup

The health check and restart steps are injectable callables. In real use the
default ``health_check`` would poll the Wazuh REST API ``GET /manager/status``
(or run ``systemctl status wazuh-manager`` over SSH) and the restart callable
would restart the manager so it reloads the new rules. For tests, pass simple
functions returning ``True``/``False`` to simulate healthy/unhealthy managers.
"""

import shutil
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _default_health_check() -> bool:
    """Default manager health probe.

    In a real deployment this would query the Wazuh API ``/manager/status``
    endpoint or shell out to ``systemctl is-active wazuh-manager`` and return
    whether the manager is running and the new ruleset loaded cleanly. Here it
    optimistically reports healthy so the orchestration can be exercised
    without a live manager; tests inject their own ``check_fn``.
    """
    return True


def _default_restart() -> None:
    """Default restart hook: no-op.

    A real implementation would restart the Wazuh manager (API
    ``PUT /manager/restart`` or ``systemctl restart wazuh-manager``) so that the
    freshly deployed rules are loaded.
    """
    return None


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def backup_rules(deploy_path: Path, backup_dir: Path | None = None) -> Path | None:
    """Back up existing ``*.xml`` rules from ``deploy_path``.

    Copies every ``.xml`` file currently in ``deploy_path`` into a fresh
    timestamped directory under ``backup_dir`` (defaults to
    ``deploy_path.parent / "rule_backups"``).

    Returns the backup directory path, or ``None`` if there was nothing to back
    up (missing deploy path or no XML files present).
    """
    deploy_path = Path(deploy_path)
    if not deploy_path.exists() or not deploy_path.is_dir():
        return None

    xml_files = sorted(deploy_path.glob("*.xml"))
    if not xml_files:
        return None

    if backup_dir is None:
        backup_dir = deploy_path.parent / "rule_backups"
    backup_dir = Path(backup_dir)

    target = backup_dir / f"backup_{_timestamp()}"
    target.mkdir(parents=True, exist_ok=True)

    for xml_file in xml_files:
        shutil.copy2(xml_file, target / xml_file.name)

    return target


def deploy_rules(src_dir: Path, deploy_path: Path, view: str = "by_tactic") -> int:
    """Copy rule XML files into ``deploy_path``.

    ``src_dir`` is expected to be the ``database/rules/<view>`` directory. If
    ``src_dir`` does not already end in ``view`` and a ``view`` subdirectory
    exists beneath it, that subdirectory is used as the source. Creates
    ``deploy_path`` if it is missing.

    Returns the number of files copied.
    """
    src_dir = Path(src_dir)
    candidate = src_dir / view
    if src_dir.name != view and candidate.is_dir():
        src_dir = candidate

    if not src_dir.exists() or not src_dir.is_dir():
        return 0

    deploy_path = Path(deploy_path)
    deploy_path.mkdir(parents=True, exist_ok=True)

    copied = 0
    for xml_file in sorted(src_dir.glob("*.xml")):
        shutil.copy2(xml_file, deploy_path / xml_file.name)
        copied += 1

    # Project-defined parent rules (e.g. the PowerShell channel parent SID
    # 91801) live in the rules root, outside the per-view subdirectories.
    # They must accompany any view so detection rules that chain off them
    # have a valid parent. Deploy them regardless of the selected view.
    parent_rules = src_dir.parent / "parent_rules.xml"
    if parent_rules.is_file():
        shutil.copy2(parent_rules, deploy_path / parent_rules.name)
        copied += 1

    return copied


def restore_backup(backup_dir: Path, deploy_path: Path) -> int:
    """Copy backed-up XML files from ``backup_dir`` back into ``deploy_path``.

    Returns the number of files restored. Tolerant of a missing/empty backup.
    """
    if backup_dir is None:
        return 0
    backup_dir = Path(backup_dir)
    if not backup_dir.exists() or not backup_dir.is_dir():
        return 0

    deploy_path = Path(deploy_path)
    deploy_path.mkdir(parents=True, exist_ok=True)

    restored = 0
    for xml_file in sorted(backup_dir.glob("*.xml")):
        shutil.copy2(xml_file, deploy_path / xml_file.name)
        restored += 1
    return restored


def health_check(check_fn=None) -> bool:
    """Run the manager health check.

    ``check_fn`` is an injectable callable returning a truthy value when the
    manager is healthy; it defaults to :func:`_default_health_check`. Returns a
    plain ``bool``. Any exception raised by ``check_fn`` is treated as unhealthy.
    """
    fn = check_fn or _default_health_check
    try:
        return bool(fn())
    except Exception:
        return False


def deploy_with_rollback(
    src_dir: Path,
    deploy_path: Path,
    view: str = "by_tactic",
    check_fn=None,
    restart_fn=None,
    backup_dir: Path | None = None,
) -> dict:
    """Deploy rules with automatic rollback on an unhealthy manager.

    Steps: back up existing rules -> deploy new rules -> run ``restart_fn`` ->
    run the health check. If the health check fails and a backup was taken, the
    backup is restored into ``deploy_path``.

    Returns a summary dict::

        {
            "deployed": <int files copied>,
            "backed_up": <bool>,
            "healthy": <bool>,
            "rolled_back": <bool>,
            "backup_path": <str path or None>,
        }
    """
    deploy_path = Path(deploy_path)
    restart_fn = restart_fn or _default_restart

    backup_path = backup_rules(deploy_path, backup_dir)
    backed_up = backup_path is not None

    deployed = deploy_rules(src_dir, deploy_path, view=view)

    restart_fn()

    healthy = health_check(check_fn)

    rolled_back = False
    if not healthy and backed_up:
        # Clear the freshly deployed files, then restore the known-good set so
        # the deploy_path matches the pre-deploy backup exactly.
        for xml_file in deploy_path.glob("*.xml"):
            xml_file.unlink()
        restore_backup(backup_path, deploy_path)
        rolled_back = True

    return {
        "deployed": deployed,
        "backed_up": backed_up,
        "healthy": healthy,
        "rolled_back": rolled_back,
        "backup_path": str(backup_path) if backup_path else None,
    }
