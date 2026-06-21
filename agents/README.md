# Agents — Custom Asset Onboarding (Part Two)

Part one of this project builds Wazuh rules from EVTX attack samples and SigmaHQ. **Part two**
adds the ability to onboard an **arbitrary new asset** — a firewall, appliance, or app whose logs
Wazuh doesn't decode out of the box — using two cooperating **Claude Code subagents**.

```
  raw log folder (one asset)
            │
            ▼
   ┌─────────────────┐     <asset>_decoder.xml   ┌──────────────┐     <asset>.xml
   │  decoder-agent  │ ───▶ + <asset>_schema.json │  rule-agent  │ ───▶ Wazuh rules
   └─────────────────┘                            └──────────────┘
       parses fields                                builds detections
```

## The two agents

| Agent | Folder | Input | Output |
|-------|--------|-------|--------|
| **decoder-agent** | `agents/decoder-agent/` | A folder of raw logs for **one** asset + an asset slug | `database/decoders/<asset>_decoder.xml` + `database/decoders/<asset>_schema.json` |
| **rule-agent** | `agents/rule-agent/` | The `<asset>_schema.json` from the decoder-agent | `database/rules/by_source/<asset>.xml` |

Each agent is defined by an `AGENT.md` file (YAML frontmatter + system prompt). They are
registered for Claude Code in `.claude/agents/` so the `Task` tool can dispatch them by name or
description.

## The contract between them

The decoder-agent emits a **field schema** (`agents/schemas/field_schema.schema.json`) describing
every field the decoder extracts, its Wazuh reference (`srcip`, `data.command`, …), type, a real
example, and which fields are security-relevant. The rule-agent reads only this schema, so it can
never reference a field the decoder didn't actually parse.

## Usage

In a Claude Code session in this repo:

```
# 1. Build a decoder + schema from a log folder
Use the decoder-agent on the logs in data/raw_logs/cisco-asa/ (asset slug: cisco-asa)

# 2. Build rules from the schema it produced
Use the rule-agent on database/decoders/cisco-asa_schema.json
```

Or invoke explicitly via the `Task` tool with `subagent_type: decoder-agent` /
`subagent_type: rule-agent`.

## Worked example

A complete Cisco ASA example ships in the `examples/` folders:

- `agents/decoder-agent/examples/cisco-asa.sample.log` — raw input
- `agents/decoder-agent/examples/cisco-asa_decoder.xml` — decoder the agent would write
- `agents/decoder-agent/examples/cisco-asa_schema.json` — the field-schema contract
- `agents/rule-agent/examples/cisco-asa_rules.xml` — rules built from that schema

## Deploying what the agents produce

1. Copy `database/decoders/<asset>_decoder.xml` → `/var/ossec/etc/decoders/`
2. Copy `database/rules/by_source/<asset>.xml` → `/var/ossec/etc/rules/`
3. Restart the Wazuh manager (or use this repo's `docker compose up`).
4. Verify by piping sample lines through `/var/ossec/bin/wazuh-logtest`.

## Conventions the agents honor

- Wazuh decoder/rule XML syntax; standard field names where possible, `data.*` for the rest.
- OSRegex dot inversion (`.` literal, `\.` any char) — or explicit `type="pcre2"`, stated per file.
- Rule IDs in the project's `100000–119999` range, partitioned per MITRE tactic (`config.yaml`).
- No empty `<field>`/`<order>` elements (the deploy pipeline rejects them).
