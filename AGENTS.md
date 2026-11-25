# NEXUS contributor instructions

- Read README and docs/VALIDATION before changing behavior. Run relevant unit/HTTP tests and JS/PowerShell syntax checks for changes.
- Preserve preview/hash/explicit approval before external AI calls. Never publish credentials, auth files, private logs, runtime databases or VM images.
- Test using synthetic fixtures/mocks by default. Real lab or paid model calls require the user's authorized scope; do not automate attacks or apply rules as part of tests.
- Keep development separate from held-out evaluation. AI output, XML parsing and unit tests do not establish detection efficacy.
- Helper operations remain explicit and lab-only, with duplicate-ID checks, configuration validation, benign/regression checks and rollback.
- Use only the NEXUS brand for product UI. Keep research/AI_USAGE truthful; do not add generated-by watermarks or AI co-author signatures.
- Do not delegate to subagents unless explicitly requested. Preserve user changes and existing Git history; never force-push without an explicit instruction.
