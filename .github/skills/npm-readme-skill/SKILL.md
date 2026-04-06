---
name: npm-readme-skill
description: "Generate or update a README.md for an npm library project. Use when: creating a new README, updating an existing README, documenting an npm package, writing npm library docs, generating package documentation for npmjs.com. Produces consistent, high-quality READMEs for npm libraries by scanning the project, collecting missing information from the user, and applying the README-template.md structure."
argument-hint: "Optional: path to the npm project (defaults to current workspace root)"
---

# npm README Generator

Generates or updates a `README.md` for an npm library following the project's README template. The template is located at [`./README-template.md`](./README-template.md) — always read it before generating. The `<!-- AI: ... -->` annotations inside the template are your section-level instructions; follow them precisely.

## When to Use

- Creating a first `README.md` for an npm package
- Updating an existing README to match the template structure and quality bar
- Documenting a library that is (or will be) published to npmjs.com

---

## Procedure

Work through all phases in order. Do **not** skip phases even if some data seems obvious. Complete each phase before starting the next.

---

### Phase 1 — Read the Template

Read [`./README-template.md`](./README-template.md) in full before doing anything else. Understand:

- The mandatory sections and their order
- Every `<!-- AI: ... -->` annotation (these are your generation rules)
- Every `<!-- OPTIONAL: ... → REMOVE IF NOT APPLICABLE -->` guard (these mark conditionally included sections)
- The `{PLACEHOLDER}` token convention

---

### Phase 2 — Scan the Project

Collect as much information as possible automatically before asking the user anything. Check all of the following:

#### Package identity
- `package.json` → `name`, `version`, `description`, `license`, `main`, `exports`, `type`, `engines.node`, `repository`, `homepage`, `keywords`, `peerDependencies`
- If `name` is scoped (e.g. `@tsmx/json-tools`), split into `{SCOPE}` and `{PACKAGE_NAME}`

#### Repository & CI
- `.git/config` or `package.json` `repository` field → derive `{GITHUB_USER}` and `{REPO_SLUG}`
- `.github/workflows/` → list workflow files; note file names for the CI badge `{WORKFLOW_FILE}`
- `.coveralls.yml` or `coveralls` in `package.json` `scripts` → Coveralls configured?

#### Test framework & coverage
- `package.json` `devDependencies` / `scripts` → jest, mocha, vitest, c8, nyc, istanbul?
- `jest.config.*`, `vitest.config.*`, `.nycrc` present?

#### Module format
- `package.json` `"type": "module"` → ESM-first; show ESM snippet in Usage
- `package.json` `exports` field with both `require` and `import` → dual CJS+ESM; show both snippets

#### Optional section signals — scan for all of these (list is not exhaustive)

The examples below are a starting point. Use your own judgment to identify any additional sections that would genuinely help a developer understand, integrate, or trust this library. Anything meaningfully present in the project is a candidate — do not limit yourself to the rows in this table.

| Signal | Optional section to propose |
|--------|----------------------------|
| Function/constructor accepts an options `Object` parameter (scan exported API) | **Options / Configuration** |
| `process.env` references in source, `.env.example`, required environment variables | **Setup & Integration** |
| `NODE_ENV`-based file naming, `conf/` directory, config file loading logic | **Naming Conventions** |
| `CHANGELOG.md`, `HISTORY.md`, multiple semver git tags, or notable version history in git log (see Changelog note below) | **Changelog** |
| `sbom/` directory or `cyclonedx` in dependencies | **SBOM** |
| `package.json` major version ≥ 2, `BREAKING CHANGE` commits in git log, migration notes in any file | **Migration / Upgrading** |
| TypeScript support: `tsconfig.json`, `.d.ts` files, `types` in `package.json` | TypeScript usage note inside the Usage section |
| CLI binary declared in `package.json` `bin` field | **CLI / Command-line Usage** |
| `SECURITY.md`, known CVEs, or security-sensitive logic (crypto, auth, input validation) | **Security** |
| `CONTRIBUTING.md`, issue/PR templates, or open-source governance files | **Contributing** |
| Meaningful benchmark results or performance-sensitive design (e.g. streaming, zero-copy) | **Performance** |
| License is not a common permissive license (not MIT/Apache/ISC), or dual-licensed | **License details** |

**Changelog — additional git analysis:** When a Changelog section is relevant, run `git log --oneline --decorate` (or equivalent) to inspect version tags and commit messages. Look for:
- Tags following semver (`v1.0.0`, `v2.0.0`, …) — list them as version headings
- Commits containing `BREAKING CHANGE`, `feat!`, or `fix!` — surface as breaking-change notes
- Commits with `feat:` or significant `fix:` messages grouped under the nearest tag — include as notable changes per version

Use this git data to populate the Changelog section with real content rather than placeholder entries, and to detect breaking changes that also warrant a **Migration / Upgrading** section.

#### Existing README
- `README.md` present? → **Update mode**: read it, identify which sections already exist, which are missing or outdated, and which need reformatting to match the template. Preserve any project-specific content not covered by the template.

---

### Phase 3 — Evaluate Badge Coverage

A good README has **3–5 badges or more**. Assess the available badge data:

| Badge | Available when |
|-------|---------------|
| License | Always — `license` field in `package.json` |
| npm version | Always — package is or will be on npmjs.com |
| Node.js version | Always — `engines.node` in `package.json`, or reasonable default |
| CI Build Status | `.github/workflows/` exists with a build/test workflow |
| Coverage (Coveralls) | `GET https://coveralls.io/github/{GITHUB_USER}/{REPO_SLUG}.json` returns HTTP 200 with a valid `covered_percent` value |
| TypeScript types | `types` / `typings` field in `package.json` or `.d.ts` files present |
| Bundle size (Bundlephobia) | Useful for front-end / isomorphic packages |
| npm weekly downloads | Good social proof for established packages |
| Snyk vulnerabilities | When security posture is a selling point |

**If fewer than 3 quality badges are available**, do both of the following before generating:

1. Offer to add missing infrastructure with a concrete suggestion:
   - **No CI workflow**: _"Consider adding a GitHub Actions test workflow — it only takes a few lines. I can generate a minimal `git-build.yml` for you. Want me to?"_
   - **No coverage reporting**: _"No coverage data was found at `coveralls.io/github/{GITHUB_USER}/{REPO_SLUG}`. Coveralls is free for open-source repos and only requires a small addition to your CI workflow. Want me to generate the setup steps for you?"_
2. Suggest additional badges that require no new tooling (npm downloads, Bundlephobia, TypeScript badge) so the user can choose alternatives.
3. Never silently omit a badge row. Always include at minimum the three unconditional badges: License, npm version, Node version.

---

### Phase 4 — Identify and Propose Optional Sections

Based on the signals collected in Phase 2, compile the list of optional sections that are relevant for **this specific project**. Do not limit yourself to the examples in the signal table — consider anything that would genuinely help a developer understand, integrate, or trust this library. Think about the library's domain, complexity, target audience, and any unusual characteristics surfaced during scanning.

For each candidate section, note the concrete evidence that justifies it (a file found, a pattern in the source, git history, etc.).

Present the complete list to the user in **one single message** using this format:

> Based on the project scan, the following optional README sections look relevant:
> - **Options / Configuration** — main export accepts an options object (`src/index.js` line 12)
> - **Setup & Integration** — `CONFIG_ENCRYPTION_KEY` env variable required at runtime
> - **Changelog** — 4 semver tags found in git history; 2 breaking changes in commit log
> - **{Any other section identified}** — {concrete reason}
>
> Should I include all of them, or would you like to exclude any?

Wait for the user's confirmation before proceeding to Phase 5.

---

### Phase 5 — Collect Missing Information

Identify every `{PLACEHOLDER}` that could not be resolved automatically. Group by importance:

#### Mandatory fields — block generation and warn if any are missing
Do not proceed to Phase 6 until all mandatory fields are known. If any cannot be resolved from the project, ask explicitly:

| Field | Resolved from |
|-------|--------------|
| `{PACKAGE_NAME}` / `{SCOPE}` | `package.json` `name` |
| `{GITHUB_USER}` / `{REPO_SLUG}` | `package.json` `repository` or `.git/config` |
| `{SHORT_TAGLINE}` | `package.json` `description` (use as starting point; rewrite if too generic) |
| Public API surface | Entry point file (`main` / `exports`) |

> ⚠️ **If a mandatory field is missing:** _"I could not determine `{FIELD}` automatically — this is required to generate the README. Please provide it before I continue."_

#### Recommended fields — ask once, allow skip
- Expanded description paragraph — if `package.json` description is a single short phrase
- `{WORKFLOW_FILE}` — if multiple `.github/workflows/` files exist and it's ambiguous which one the CI badge should point to
- A motivating real-world use-case scenario — if a before/after example would significantly strengthen the README

Ask **all** recommended questions in **one batched message**, not one question at a time.

---

### Phase 6 — Generate or Update the README

#### Create mode (no existing README)

1. Read the template top-to-bottom.
2. Follow every `<!-- AI: ... -->` instruction literally when filling each section.
3. Replace all `{PLACEHOLDER}` tokens with resolved values.
4. Strip all `<!-- AI: ... -->` and `<!-- OPTIONAL: ... -->` comment markers — the final README must contain no template comments.
5. Remove the full optional section blocks (including their comment guards) for sections the user declined.
6. Apply badge guidance from Phase 3.
7. Apply API Reference structure precisely:
   - One H3 per function group
   - One H4 per public function, with: description → Parameters → Returns (if applicable) → Example (`// Result:` inline comments)
   - `---` horizontal rule after the last H4 of each group
8. Write to `README.md` in the project root.

#### Update mode (existing README)

1. Read the existing `README.md` in full.
2. For each mandatory template section:
   - **Missing**: add it following the template structure.
   - **Present, format matches**: keep as-is; only correct factual errors or outdated content.
   - **Present, format differs**: reformat to match the template style while preserving all content.
3. For each optional section the user approved: add it if absent, or reformat if present.
4. Badge row: add missing badges, remove stale/broken ones, apply Phase 3 suggestions.
5. Preserve any project-specific sections not covered by the template (e.g. a "Roadmap" or "Contributing" section) — move them to after the last template section.
6. Overwrite `README.md` with the result.

---

### Phase 7 — Post-generation Review

After writing the file, re-read the output and verify:

- [ ] No `{PLACEHOLDER}` tokens remain anywhere in the document
- [ ] No `<!-- AI: ... -->` or `<!-- OPTIONAL: ... -->` comment markers remain
- [ ] All four mandatory sections are present: Header, Description & Benefits, Usage, API Reference
- [ ] Badge row contains 3 or more badges
- [ ] Every API Reference function entry has: H4 signature, description, Parameters list, Returns line (or is intentionally omitted for void functions), Example code block with `// Result:` comments
- [ ] All optional section comment guards are removed

Fix any issues found before reporting to the user.

**Final report to user:** brief summary of what was created or updated, which optional sections were included, and any badge improvement suggestions that were noted but deferred.

---

### Phase 8 — Quality Assurance & Typo Fixes

After generating or updating the README, systematically check for typos, grammatical errors, and inconsistencies that could undermine quality. This phase ensures the final output is polished and professional.

#### QA Checklist

Re-read the entire README and verify all of the following:

- [ ] **No doubled words** — search for common duplicates like "the the", "a a", "and and"
- [ ] **Tech term capitalization** — consistent usage of: Node.js, npm, npm, GitHub, JavaScript, TypeScript, ESM, CommonJS, ESM, CommonJS, Coveralls, Bundlephobia, Snyk
- [ ] **Punctuation & spacing**
  - No missing periods at end of sentences
  - No extra spaces (e.g., double spaces between words)
  - No orphaned punctuation (e.g., comma or period hanging alone)
  - Consistent use of em-dashes (` — `) vs hyphens (` - `)
- [ ] **Code block correctness**
  - Every code fence has a language tag (`javascript`, `json`, `bash`, `yaml`, etc.)
  - Code blocks that show output include `// Result:` comments
  - No mismatched or unclosed backticks
- [ ] **Markdown format integrity**
  - All links are properly formatted: `[text](url)` with no bare URLs
  - No broken link anchors or malformed markdown
  - All heading levels follow the template (H1 title, H2 sections, H3 groups, H4 items)
- [ ] **Trailing whitespace** — no extra spaces or tabs at end of lines
- [ ] **Section consistency**
  - Badge bullets are consecutive with no blank lines between them
  - Feature bullets have emoji prefix + link to API Reference H3 anchor
  - API Reference H4 signatures are consistently formatted with backticks
  - Parameters lists are bullet lists with consistent entry format

#### Common Typos in npm READMEs

Watch for these frequent mistakes:

| Typo | Correction |
|------|------------|
| installl | install |
| recieve | receive |
| arugment | argument |
| fucntion | function |
| paremeter | parameter |
| dependancy | dependency |
| asyncronous | asynchronous |
| javascript | JavaScript |
| node | Node.js |
| npm | npm (lowercase) |
| github | GitHub |
| coveralls | Coveralls |
| bundlephobia | Bundlephobia |

#### Process

1. **Re-read the entire README top-to-bottom** — catch surface-level errors as you scan
2. **Run through the QA Checklist above** — verify each item systematically
3. **Search for common typos** — use your editor's find-replace to hunt for patterns ("the the", doubled words, etc.)
4. **Check API Reference formatting** — ensure every function entry has description, Parameters, Returns (if applicable), and Example with `// Result:` comments
5. **Verify all placeholders are gone** — final scan for stray `{PLACEHOLDER}` tokens
6. **Fix all issues found** — apply corrections immediately
7. **Final read-through** — spot-check the corrected areas before delivering to user

---

## Formatting & Style Rules

These rules apply to the entire generated README and override any conflicting conventions:

- **Badges**: on consecutive lines, no blank lines between them, placed above the H1 title.
- **H1 title**: package name, optionally hyperlinked to GitHub. Scope prefix included: `# [**@scope/name**](https://github.com/user/repo)`.
- **Tagline**: a blockquote (`>`), one sentence, no trailing period, immediately below the H1.
- **Feature bullets**: one emoji prefix per capability group; sub-bullets indented under the group label; group label is a link to its API Reference H3 anchor.
- **Code blocks**: always declare the language fence (`javascript`, `json`, `bash`, `yaml`). Use `const` for all inputs. Show output as `// Result: ...` inline comments, not as separate prose.
- **API Reference H3 headers**: `### {Label} (\`{export}\`)` — export name in inline code. Omit the parenthetical for top-level / default exports.
- **API Reference H4 signatures**: `` #### `export.method(param1, param2?)` `` — mark optional parameters with `?`.
- **Parameters block**: bullet list; each entry: `` `name` (Type, optional): description. Default: `value` ``.
- **Horizontal rule** (`---`): separates API Reference groups (after last H4 of each group) and major document sections.
- **No emoji in H2/H3/H4 headings** — emoji is reserved for feature bullet groups only.
- **No template comment markers in output** — strip every `<!-- AI: -->` and `<!-- OPTIONAL: -->` block before writing the file.
