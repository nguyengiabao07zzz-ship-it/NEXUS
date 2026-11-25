# NEXUS release checkpoint — 25/11/2026

Status: lab evaluation build, not production certification.

Included: Indexer intake; local grouping/filter/priority; explicit reviewed-context AI preview; Codex ChatGPT/OpenAI API adapters; triage and development-only rule drafts; history; candidate bundle/helper; bounded local polling; startup diagnostics and guides.

Local validation before publication:108 tests pass; JS syntax and PowerShell parsing pass. UI checked on separate synthetic/mocked fixture. Two latest model smoke tests used synthetic JSON only. Live Wazuh stage/activation/rollback, attack replay and measured efficacy remain pending user lab evaluation. See docs/VALIDATION.md.

GitHub CI is configured for Windows/Linux and Python3.11/3.12. A configured workflow is not a passed run; consult Actions for remote results.

Source continues the team's LLM-in-Wazuh project. This public repository excludes internal project/competition/team files, old machine-specific notes and all private runtime data. It does not replace a private backup of development records.
