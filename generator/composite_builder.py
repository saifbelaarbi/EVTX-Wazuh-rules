"""Build composite / chained correlation Wazuh rules.

A composite rule ties together a sequence of stages (each an existing Wazuh
rule) into a single higher-confidence alert using Wazuh's correlation
primitives: ``<if_matched_sid>`` / ``<if_sid>``, the ``frequency`` and
``timeframe`` rule attributes, and ``<same_field>`` to require a shared value
(user, host, image, ...) across the correlated events.

Templates live in ``sources/composite_templates.yaml`` and describe realistic
attack chains. The stage ``if_sid`` / ``if_matched_sid`` values are placeholders
that an operator wires to real rule ids; the builder always emits valid XML.
"""

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml
from lxml import etree

from .id_manager import allocate_id

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEMPLATES_PATH = PROJECT_ROOT / "sources" / "composite_templates.yaml"


@dataclass
class CompositeRuleSpec:
    """Declarative description of a composite/chained correlation rule."""

    name: str
    description: str
    tactic: str
    stages: list[dict]
    frequency: int = 2
    timeframe: int = 300
    level: int = 12
    mitre_ids: list = field(default_factory=list)


def _last_matched_sid(stages: list[dict]) -> int | None:
    """Return the if_matched_sid of the last stage that declares one."""
    for stage in reversed(stages):
        if "if_matched_sid" in stage:
            return stage["if_matched_sid"]
    return None


def _same_field_for(stages: list[dict]) -> str | None:
    """Return the same_field declared on the correlated (matched) stage, if any."""
    for stage in reversed(stages):
        if stage.get("same_field"):
            return stage["same_field"]
    return None


def build_composite_rule(spec: CompositeRuleSpec) -> dict:
    """Build a Wazuh composite correlation rule dict from a spec.

    Returns the same dict shape as ``rule_builder.build_rule``:
    ``{id, level, xml_element, metadata, pattern}`` with ``pattern=None``.
    """
    rule_id = allocate_id("composite")

    rule_elem = etree.Element(
        "rule",
        id=str(rule_id),
        level=str(spec.level),
        frequency=str(spec.frequency),
        timeframe=str(spec.timeframe),
    )

    # Prerequisite stages become <if_sid> references; the final correlated
    # stage becomes the <if_matched_sid> that, when seen `frequency` times in
    # `timeframe`, triggers the alert.
    matched_sid = _last_matched_sid(spec.stages)
    parent_sid = None
    for stage in spec.stages:
        if "if_sid" in stage:
            if_sid_elem = etree.SubElement(rule_elem, "if_sid")
            if_sid_elem.text = str(stage["if_sid"])
            if parent_sid is None:
                parent_sid = stage["if_sid"]

    if matched_sid is not None:
        matched_elem = etree.SubElement(rule_elem, "if_matched_sid")
        matched_elem.text = str(matched_sid)
        if parent_sid is None:
            parent_sid = matched_sid

    same_field = _same_field_for(spec.stages)
    if same_field:
        etree.SubElement(rule_elem, "same_field", name=same_field)

    desc = etree.SubElement(rule_elem, "description")
    desc.text = spec.description

    if spec.mitre_ids:
        mitre = etree.SubElement(rule_elem, "mitre")
        for mid in spec.mitre_ids:
            id_elem = etree.SubElement(mitre, "id")
            id_elem.text = str(mid)

    group = etree.SubElement(rule_elem, "group")
    group.text = "composite,chained,"

    metadata = {
        "rule_id": rule_id,
        "tactic": spec.tactic,
        "technique_name": spec.name,
        "source_evtx": "",
        "source_category": "composite",
        "parent_sid": parent_sid if parent_sid is not None else 0,
        "confidence": "high",
        "created": date.today().isoformat(),
        "field_matches": {},
        "mitre_ids": list(spec.mitre_ids),
        "frequency": spec.frequency,
        "timeframe": spec.timeframe,
        "same_field": same_field,
        "stages": spec.stages,
    }

    return {
        "id": rule_id,
        "level": spec.level,
        "xml_element": rule_elem,
        "metadata": metadata,
        "pattern": None,
    }


def load_templates(path: Path | None = None) -> list[CompositeRuleSpec]:
    """Load composite rule templates from a YAML file into specs."""
    path = Path(path) if path is not None else DEFAULT_TEMPLATES_PATH
    with open(path) as f:
        raw = yaml.safe_load(f) or []

    specs: list[CompositeRuleSpec] = []
    for entry in raw:
        specs.append(
            CompositeRuleSpec(
                name=entry["name"],
                description=entry["description"],
                tactic=entry["tactic"],
                stages=entry.get("stages", []),
                frequency=entry.get("frequency", 2),
                timeframe=entry.get("timeframe", 300),
                level=entry.get("level", 12),
                mitre_ids=entry.get("mitre_ids", []) or [],
            )
        )
    return specs


def build_from_templates(templates: list[CompositeRuleSpec] | None = None) -> list[dict]:
    """Build composite rule dicts from templates (loaded from YAML if not given)."""
    if templates is None:
        templates = load_templates()
    return [build_composite_rule(spec) for spec in templates]
