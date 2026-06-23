"""Validate generated Wazuh rules for correctness and consistency."""

import json
import re
from pathlib import Path

from lxml import etree
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULE_INDEX_FILE = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"

# Valid MITRE technique ID pattern
MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# A lone (odd-count) backslash escaping a char that is NOT escapable in Wazuh
# OSRegex. ``+ * ? { } [ ]`` must not be escaped — e.g. ``\+`` / ``\{`` are
# invalid sequences Wazuh rejects with error 5107 (CRITICAL, aborts the whole
# rule file). (``+``/``*`` are quantifiers that apply only to a preceding
# backslash-class, so standalone they are already literal.) lxml/PCRE accept
# these, so this is a Wazuh-specific check the generic XML parse won't catch.
_BAD_OSREGEX_ESCAPE = re.compile(r"(?<!\\)(?:\\\\)*\\([{}\[\]?+*])")

# An odd-count trailing backslash in element text. OS_XML treats ``\`` as an
# escape char, so ``\</tag>`` escapes the ``<`` and Wazuh reports the element as
# "not closed" (error 1226, CRITICAL). ``\\`` (even) is a safe literal backslash.
_TRAILING_BACKSLASH = re.compile(r"(?<!\\)(?:\\\\)*\\$")


def validate_xml_wellformed(rule: dict) -> list[str]:
    """Check XML well-formedness."""
    errors = []
    try:
        xml_str = etree.tostring(rule["xml_element"], encoding="unicode")
        etree.fromstring(xml_str)
    except Exception as e:
        errors.append(f"Rule {rule['id']}: XML malformed - {e}")
    return errors


def validate_required_elements(rule: dict) -> list[str]:
    """Check that required elements are present."""
    errors = []
    elem = rule["xml_element"]

    # Must have id
    if not elem.get("id"):
        errors.append(f"Rule {rule['id']}: Missing 'id' attribute")

    # Must have level
    if not elem.get("level"):
        errors.append(f"Rule {rule['id']}: Missing 'level' attribute")

    # Must have description
    desc = elem.find("description")
    if desc is None or not desc.text:
        errors.append(f"Rule {rule['id']}: Missing or empty 'description'")

    # Must have if_sid or if_group
    if_sid = elem.find("if_sid")
    if_group = elem.find("if_group")
    if if_sid is None and if_group is None:
        errors.append(f"Rule {rule['id']}: Missing 'if_sid' or 'if_group'")

    return errors


def validate_id_range(rule: dict) -> list[str]:
    """Check rule ID is in the custom range."""
    errors = []
    rule_id = rule["id"]
    if not (100000 <= rule_id <= 119999):
        errors.append(f"Rule {rule_id}: ID outside Wazuh custom range (100000-119999)")
    return errors


def validate_id_uniqueness(rules: list[dict]) -> list[str]:
    """Check for duplicate rule IDs."""
    errors = []
    seen_ids = {}
    for rule in rules:
        rid = rule["id"]
        if rid in seen_ids:
            errors.append(f"Rule {rid}: Duplicate ID (also in {seen_ids[rid]})")
        seen_ids[rid] = rule["metadata"].get("source_evtx", "unknown")

    # Also check against existing index
    if RULE_INDEX_FILE.exists():
        with open(RULE_INDEX_FILE) as f:
            existing = json.load(f)
        for rule in rules:
            if str(rule["id"]) in existing:
                errors.append(f"Rule {rule['id']}: Conflicts with existing rule in index")

    return errors


def validate_alert_level(rule: dict) -> list[str]:
    """Check alert level is valid."""
    errors = []
    level = int(rule["xml_element"].get("level", "0"))
    if level < 0 or level > 15:
        errors.append(f"Rule {rule['id']}: Invalid alert level {level} (must be 0-15)")
    if level == 0:
        errors.append(f"Rule {rule['id']}: Alert level is 0 (will not generate alerts)")
    return errors


def validate_mitre_ids(rule: dict) -> list[str]:
    """Validate MITRE ATT&CK technique IDs."""
    errors = []
    mitre = rule["xml_element"].find("mitre")
    if mitre is not None:
        for id_elem in mitre.findall("id"):
            if id_elem.text and not MITRE_PATTERN.match(id_elem.text):
                errors.append(f"Rule {rule['id']}: Invalid MITRE ID format '{id_elem.text}'")
    return errors


def validate_rule(rule: dict) -> list[str]:
    """Run all validations on a single rule."""
    errors = []
    errors.extend(validate_xml_wellformed(rule))
    errors.extend(validate_required_elements(rule))
    errors.extend(validate_id_range(rule))
    errors.extend(validate_alert_level(rule))
    errors.extend(validate_mitre_ids(rule))
    return errors


def validate_rules(rules: list[dict]) -> list[str]:
    """Run all validations on a list of rules."""
    all_errors = []

    # Per-rule validations
    for rule in rules:
        all_errors.extend(validate_rule(rule))

    # Cross-rule validations
    all_errors.extend(validate_id_uniqueness(rules))

    return all_errors


def validate_database(rules_dir: Path) -> list[str]:
    """Validate all XML rule files in the database."""
    errors = []

    for xml_file in rules_dir.rglob("*.xml"):
        # Wazuh's OS_XML parser cannot handle an <?xml ...?> declaration and
        # rejects the entire file (error 1226/1220). lxml accepts it, so check
        # the raw first line before parsing.
        try:
            first_line = xml_file.read_text().lstrip()[:64]
            if first_line.startswith("<?xml"):
                errors.append(
                    f"{xml_file.name}: starts with an <?xml declaration (Wazuh OS_XML rejects this — remove it)"
                )
        except OSError:
            pass

        try:
            tree = etree.parse(str(xml_file))
            root = tree.getroot()

            seen_ids = set()
            for rule_elem in root.iter("rule"):
                rule_id = rule_elem.get("id", "")
                level = rule_elem.get("level", "")

                if not rule_id:
                    errors.append(f"{xml_file.name}: Rule missing 'id'")
                    continue

                if rule_id in seen_ids:
                    errors.append(f"{xml_file.name}: Duplicate ID {rule_id}")
                seen_ids.add(rule_id)

                if not level:
                    errors.append(f"{xml_file.name}: Rule {rule_id} missing 'level'")

                desc = rule_elem.find("description")
                if desc is None or not desc.text:
                    errors.append(f"{xml_file.name}: Rule {rule_id} missing description")
                elif _TRAILING_BACKSLASH.search(desc.text):
                    errors.append(
                        f"{xml_file.name}: Rule {rule_id} description ends with a lone backslash "
                        "— Wazuh OS_XML reads it as 'element not closed' (error 1226)"
                    )

                for field_elem in rule_elem.findall("field"):
                    if field_elem.text is None or not field_elem.text.strip():
                        fname = field_elem.get("name", "?")
                        errors.append(
                            f'{xml_file.name}: Rule {rule_id} has empty <field name="{fname}"> (Wazuh rejects this)'
                        )
                    elif field_elem.text and _BAD_OSREGEX_ESCAPE.search(field_elem.text):
                        fname = field_elem.get("name", "?")
                        errors.append(
                            f"{xml_file.name}: Rule {rule_id} field '{fname}' has an invalid OSRegex "
                            "escape (\\{ \\} \\[ \\] \\?) — Wazuh error 5107 aborts the file"
                        )

        except etree.XMLSyntaxError as e:
            errors.append(f"{xml_file.name}: XML syntax error - {e}")

    return errors
