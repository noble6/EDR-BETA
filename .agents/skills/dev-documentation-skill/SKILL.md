\---

name: dev-documentation-skill

description: Use when asked to generate developer documentation, README, or architecture docs for a project by analyzing its files, folder structure, code, and configs.

\---



\# Super Dev Documentation Generator



\## Purpose

Analyze a project's actual files (folder structure, source code, configs, dependencies) and produce accurate, comprehensive developer documentation — not generic boilerplate. Documentation must reflect what the code actually does, not assumptions.



\## Process (follow in order)



1\. \*\*Inventory the project first\*\*

&#x20;  - List every file and folder in the tree; note languages, frameworks, and config files present.

&#x20;  - Identify entry points (main.py, main.rs, index.ts, daemon binaries) before writing anything.

&#x20;  - Note dependency manifests (requirements.txt, Cargo.toml, package.json) to determine the real tech stack — never guess.



2\. \*\*Extract structure before prose\*\*

&#x20;  - Build an annotated directory tree first; every file/folder gets one line explaining its purpose.

&#x20;  - Group related files into logical components (e.g., "daemon layer", "backend layer", "config layer") before describing each in depth.



3\. \*\*Trace actual behavior, not assumptions\*\*

&#x20;  - Read entry-point files to determine real startup flow, exposed endpoints/routes, and inter-component communication (APIs, IPC, sockets, DB).

&#x20;  - Cross-reference config files (`.conf`, `.env`, `.toml`, `.yaml`) to document real configurable parameters, not hypothetical ones.

&#x20;  - If code and folder names disagree, trust the code and flag the discrepancy.



\## Required Documentation Sections



\- \*\*Overview\*\* — one paragraph: what the project does, why it exists, primary tech stack.

\- \*\*Architecture\*\* — annotated directory tree + how components communicate (diagram description if complex).

\- \*\*Setup/Installation\*\* — exact steps derived from dependency files and any install scripts found in the repo.

\- \*\*Configuration Reference\*\* — every config file and its parameters, pulled directly from the actual config files present.

\- \*\*Component Reference\*\* — one subsection per major component/module, covering responsibility, key files, and inputs/outputs.

\- \*\*API/Interface Reference\*\* — if backend/API code exists, document every route/endpoint found in the code (method, path, purpose) — do not invent endpoints not present in the source.

\- \*\*Data/Database Reference\*\* — if schema files exist, document tables/fields directly from schema.sql or equivalent.

\- \*\*Deployment\*\* — startup mechanism (systemd unit, Docker, script) as found in the repo, including any hardening or security directives present.

\- \*\*Known Gaps/TODOs\*\* — call out missing pieces (no tests found, no CI config, secrets management absent) rather than silently omitting them.



\## Style Rules

\- Write short, accurate sections — cut anything not verifiable from the actual files \[web:39].

\- Use tables for structured comparisons (config parameters, API routes, dependency versions) rather than long prose.

\- Never fabricate a feature, endpoint, or file that isn't present in the provided project files.

\- Flag version/documentation drift explicitly if file contents contradict naming conventions or prior docs.

\- Keep the annotated directory tree as the single source of truth; every other section should reference it rather than repeating structure descriptions.



\## Common Pitfalls

\- Do not write documentation from the project name/description alone — always parse actual files first.

\- Do not skip configuration files just because they look like boilerplate; secrets/API endpoints there matter for setup docs.

\- Do not omit a "Known Gaps" section — undocumented gaps mislead future maintainers more than an honest gap list.

