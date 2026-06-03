"""Read-only web dashboard over the rule database.

This module is intentionally split into two layers:

1. Pure data-loader / aggregation functions (``load_index``,
   ``load_validation``, ``summary_stats``, ``filter_rules``) that depend only
   on the standard library. These can be imported and tested without any web
   framework installed.

2. An optional FastAPI application built by ``create_app()``. FastAPI is only
   imported lazily inside ``create_app`` so that importing this module never
   fails when FastAPI/uvicorn are absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEX_PATH = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"
DEFAULT_VALIDATION_PATH = PROJECT_ROOT / "database" / "metadata" / "validation_results.json"
DEFAULT_NAVIGATOR_PATH = PROJECT_ROOT / "database" / "navigator_layer.json"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


# --------------------------------------------------------------------------- #
# Pure data-loader functions (no web framework required)
# --------------------------------------------------------------------------- #
def _load_json(path: Path) -> dict:
    """Load a JSON object from ``path``; return ``{}`` if missing/invalid."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def load_index(index_path: Optional[Path] = None) -> dict:
    """Load the rule index keyed by rule id. Missing file -> ``{}``."""
    path = Path(index_path) if index_path is not None else DEFAULT_INDEX_PATH
    return _load_json(path)


def load_validation(path: Optional[Path] = None) -> dict:
    """Load validation results keyed by rule id. Missing file -> ``{}``."""
    resolved = Path(path) if path is not None else DEFAULT_VALIDATION_PATH
    return _load_json(resolved)


def load_navigator(path: Optional[Path] = None) -> dict:
    """Load the MITRE ATT&CK Navigator layer. Missing file -> ``{}``."""
    resolved = Path(path) if path is not None else DEFAULT_NAVIGATOR_PATH
    return _load_json(resolved)


def summary_stats(index: dict, validation: Optional[dict] = None) -> dict:
    """Compute summary statistics over the rule index.

    Returns a dict with keys: ``total``, ``by_tactic``, ``by_source``,
    ``pass_rate`` and ``passed``.
    """
    index = index or {}
    by_tactic: dict[str, int] = {}
    by_source: dict[str, int] = {}

    for meta in index.values():
        if not isinstance(meta, dict):
            continue
        tactic = meta.get("tactic") or "unknown"
        source = meta.get("source_category") or "unknown"
        by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1

    total = len(index)

    passed = 0
    pass_rate = 0.0
    if validation:
        considered = 0
        for result in validation.values():
            if not isinstance(result, dict):
                continue
            if result.get("inconclusive"):
                continue
            considered += 1
            if result.get("passed"):
                passed += 1
        if considered:
            pass_rate = passed / considered

    return {
        "total": total,
        "by_tactic": dict(sorted(by_tactic.items())),
        "by_source": dict(sorted(by_source.items())),
        "pass_rate": pass_rate,
        "passed": passed,
    }


def filter_rules(
    index: dict,
    tactic: Optional[str] = None,
    source: Optional[str] = None,
    q: Optional[str] = None,
) -> list[dict]:
    """Filter the rule index, returning a list of ``{id, ...meta}`` dicts.

    ``tactic`` and ``source`` match exactly against ``tactic`` and
    ``source_category``. ``q`` is a case-insensitive substring match against
    the rule id and ``technique_name``.
    """
    index = index or {}
    q_lower = q.lower() if q else None
    results: list[dict] = []

    for rule_id, meta in index.items():
        if not isinstance(meta, dict):
            continue
        if tactic is not None and meta.get("tactic") != tactic:
            continue
        if source is not None and meta.get("source_category") != source:
            continue
        if q_lower is not None:
            technique = str(meta.get("technique_name", ""))
            if q_lower not in str(rule_id).lower() and q_lower not in technique.lower():
                continue
        entry = {"id": rule_id}
        entry.update(meta)
        results.append(entry)

    results.sort(key=lambda item: str(item["id"]))
    return results


# --------------------------------------------------------------------------- #
# Optional FastAPI application
# --------------------------------------------------------------------------- #
def _render_index_html(stats: dict) -> str:
    """Render the dashboard HTML, preferring Jinja2 then inline fallback."""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        template = env.get_template("index.html")
        return template.render(stats=stats)
    except Exception:
        # Inline minimal fallback if Jinja2 or the template is unavailable.
        rows = "".join(f"<li>{tactic}: {count}</li>" for tactic, count in stats.get("by_tactic", {}).items())
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>Wazuh Rule Dashboard</title></head><body>"
            f"<h1>Wazuh Rule Dashboard</h1>"
            f"<p>Total rules: {stats.get('total', 0)}</p>"
            f"<p>Pass rate: {stats.get('pass_rate', 0.0):.1%}</p>"
            f"<ul>{rows}</ul>"
            "<p>See <a href='/api/rules'>/api/rules</a> for JSON.</p>"
            "</body></html>"
        )


def create_app(
    index_path: Optional[Path] = None,
    validation_path: Optional[Path] = None,
    navigator_path: Optional[Path] = None,
):
    """Build and return the FastAPI dashboard application.

    Raises ``RuntimeError`` with a clear message if FastAPI is not installed.
    """
    try:
        from fastapi import FastAPI, Query
        from fastapi.responses import HTMLResponse, JSONResponse
    except ImportError as exc:  # pragma: no cover - exercised only without fastapi
        raise RuntimeError(
            "FastAPI is required to run the web dashboard. Install it with: pip install fastapi uvicorn"
        ) from exc

    idx_path = index_path if index_path is not None else DEFAULT_INDEX_PATH
    val_path = validation_path if validation_path is not None else DEFAULT_VALIDATION_PATH
    nav_path = navigator_path if navigator_path is not None else DEFAULT_NAVIGATOR_PATH

    app = FastAPI(title="EVTX-Wazuh Rule Dashboard")

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        stats = summary_stats(load_index(idx_path), load_validation(val_path))
        return HTMLResponse(_render_index_html(stats))

    @app.get("/api/stats")
    def api_stats() -> JSONResponse:
        stats = summary_stats(load_index(idx_path), load_validation(val_path))
        return JSONResponse(stats)

    @app.get("/api/rules")
    def api_rules(
        tactic: Optional[str] = Query(default=None),
        source: Optional[str] = Query(default=None),
        q: Optional[str] = Query(default=None),
    ) -> JSONResponse:
        rules = filter_rules(load_index(idx_path), tactic=tactic, source=source, q=q)
        return JSONResponse(rules)

    @app.get("/api/navigator")
    def api_navigator() -> JSONResponse:
        return JSONResponse(load_navigator(nav_path))

    return app
