# Custom Asset Decoders

Wazuh decoder XML + field schemas produced by the **decoder-agent** (`agents/decoder-agent/`).

Each onboarded asset contributes two files:

- `<asset>_decoder.xml` — Wazuh `<decoder>` blocks. Deploy to `/var/ossec/etc/decoders/`.
- `<asset>_schema.json` — field-schema contract consumed by the **rule-agent**.
  Conforms to `agents/schemas/field_schema.schema.json`.

See `agents/README.md` for the full two-agent onboarding workflow and a worked Cisco ASA example.
