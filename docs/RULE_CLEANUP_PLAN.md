# Rule Cleanup Plan

Generated: 2026-04-29

## Purpose

This file turns the prior analysis into an actionable queue with exact rule IDs where possible.

Use this as the next-step worklist for any coding or review agent. It is intentionally additive and does not require modifying the existing review notes.

## Priority Order

1. Drop obviously wrong mappings.
2. Merge exact duplicate logic across tactics.
3. Rewrite generic Security event rules into contextual detections.
4. Keep and normalize the high-signal offensive-tool and credential-dumping rules.
5. Remove sample-specific brittle rules.

## Keep

These are the strongest candidates to preserve, then normalize and deduplicate where needed.

### PowerShell credential-dumping and offensive-tool indicators

- `101573` `sekurlsa::`
- `101574` `sekurlsa::`
- `101577` `lsadump::`
- `101578` `lsadump::`
- `101579` `invoke-mimikatz`
- `105017` `minidump`
- `105033` `comsvcs.dll`

Rationale:
- These are high-signal artifact matches.
- They are closer to attacker tradecraft than to generic admin behavior.

### Sysmon credential-dumping and offensive-tool indicators

- `105025` `dumpert`
- `105028` `comsvcs.dll`
- `105029` `minidump`
- `101006` `procdump`
- `105024` `procdump`

Rationale:
- These are useful rule seeds for real credential-dumping behavior.
- Some may still need ATT&CK cleanup, but the underlying logic is worth preserving.

### WMI persistence indicators

- `102022`
- `102023`
- `102024`

Rationale:
- WMI event subscription activity is a meaningful persistence detection surface.

## Merge

These groups have identical logic across multiple tactics and should be collapsed into one canonical rule per group.

### Group A: `rundll32` process match

- `101000`
- `102008`
- `103000`
- `104000`
- `105008`
- `107005`

Recommended canonical bucket:
- keep one execution-oriented rule
- reclassify related ATT&CK mapping only if extra context exists

### Group B: PowerShell `-nop`

- `101570`
- `104004`
- `105004`
- `107002`

Recommended canonical bucket:
- keep one execution or defense-evasion rule

### Group C: `psexesvc` process match

- `101565`
- `102007`
- `103004`
- `107006`

Recommended canonical bucket:
- keep one lateral-movement or service-execution rule depending on context

### Group D: PowerShell `bypass`

- `101025`
- `104006`
- `106002`
- `107007`

Recommended canonical bucket:
- keep one low/medium-confidence PowerShell execution rule

### Group E: executable dropped in `\appdata\`

- `101028`
- `102036`
- `103011`
- `104020`
- `107019`

Recommended canonical bucket:
- keep one suspicious file-drop rule

### Group F: DLL loaded from `\public\`

- `102017`
- `103022`
- `104008`
- `105014`

Recommended canonical bucket:
- keep one suspicious DLL path rule

### Group G: executable dropped in `\temp\`

- `101030`
- `102033`
- `103010`
- `104029`
- `107026`

Recommended canonical bucket:
- keep one suspicious temp-path file-drop rule

### Group H: explicit credential logon `4648`

- `101559`
- `103009`
- `105036`
- `107013`
- `109012`

Recommended canonical bucket:
- keep one contextual authentication rule

### Group I: special privilege assignment `4672`

- `101063`
- `102062`
- `103006`
- `104030`
- `105023`
- `106005`
- `107009`
- `109013`

Recommended canonical bucket:
- keep one contextual privilege-enrichment rule only

### Group J: remote logon type `3`

- `101064`
- `102048`
- `103007`
- `104015`
- `105018`
- `106006`
- `107008`
- `109014`

Recommended canonical bucket:
- keep one low-priority remote logon rule, preferably under lateral movement or authentication context

### Group K: DLL loaded from `\programdata\`

- `101045`
- `102032`
- `104018`
- `107023`

Recommended canonical bucket:
- keep one suspicious DLL path rule

### Group L: executable dropped in `\programdata\`

- `101048`
- `102030`
- `104019`
- `107018`

Recommended canonical bucket:
- keep one suspicious file-drop rule

### Group M: scheduled task created `4698`

- `101057`
- `102046`
- `103008`
- `107012`

Recommended canonical bucket:
- keep one scheduled-task rule, then rewrite it to include stronger context

## Rewrite

These rules should not survive in their current form, but the detection idea may still be useful.

### Generic Security event families

Rewrite these families to use additional fields, chains, or contextual correlation:

- `101057`
- `101063`
- `101064`
- `102046`
- `102048`
- `102062`
- `103006`
- `103007`
- `103008`
- `103009`
- `104015`
- `105018`
- `105023`
- `105036`
- `106005`
- `106006`
- `107008`
- `107009`
- `107012`
- `107013`
- `109012`
- `109013`
- `109014`

Rationale:
- These mostly key on bare Windows event IDs such as `4624`, `4648`, `4672`, and `4698`.
- They are repeated across tactics and lack enough context for strong standalone detections.

### Service-installation family with brittle `serviceName` values

Rewrite or remove the early execution service rules:

- `101069`
- `101070`
- `101071`
- `101072`
- `101073`
- `101074`
- `101075`
- `101076`
- `101077`
- `101078`
- `101079`
- `101080`
- `101081`
- `101082`
- `101083`
- `101084`
- `101085`
- `101086`
- `101087`
- `101088`
- `101089`
- `101090`

Rationale:
- These rules include sample-specific `serviceName` content and are not portable.
- The stable part is the suspicious `imagePath` fragment, not the exact service name.

### PowerShell rules with weak ATT&CK mapping

Review and likely rewrite:

- `105034` `invoke-wmimethod`
- `105035` `stop-service`
- `104025` `invoke-mimikatz` currently under defense evasion
- `104026` `invoke-expression`
- `104027` `downloadstring`
- `104028` `sekurlsa::`

Rationale:
- The strings are useful, but the current ATT&CK and tactic assignment is source-path-driven rather than behavior-driven.

## Drop

These are the first candidates to remove entirely unless they are rewritten from scratch.

### Wrong or indefensible ATT&CK conclusions from generic events

- `100000` failed logon `4625` mapped to phishing `T1566`
- `104012` user account creation `4720` mapped to process injection `T1055`

### Pure sample-overfit service rules

Drop if not rewritten:

- `101069`
- `101070`
- `101071`
- `101072`
- `101073`
- `101074`
- `101075`
- `101076`
- `101077`
- `101078`
- `101079`
- `101080`
- `101081`
- `101082`
- `101083`
- `101084`
- `101085`
- `101086`
- `101087`
- `101088`
- `101089`
- `101090`

### Duplicate logic that should not coexist after cleanup

After selecting a canonical rule for each merge group, drop the remaining duplicates in:

- Group A through Group M above

## Suggested Canonicalization Rules

- Prefer `execution` for generic process and PowerShell tool matches unless better context exists.
- Prefer `lateral_movement` only when the event itself proves remote-service behavior.
- Prefer `credential_access` only when the string or event clearly indicates dumping, LSASS access, tickets, or secrets extraction.
- Keep generic `4624`, `4648`, `4672`, and `4698` detections low-severity and contextual.
- Do not derive ATT&CK technique purely from the EVTX sample folder name.

## Best Next Implementation Task

Create a new normalization pass in the generator that:
- deduplicates by `field_matches + parent_sid`
- chooses one canonical tactic per detection family
- suppresses sample-specific values like exact service names
- flags generic Security event rules for manual review instead of auto-approval
