<!-- AI: HEADER SECTION
     Generate shield badges from https://shields.io/.
     Include ALL of the badges below that apply to this package.
     Remove any badge whose data source does not exist for this project.
     Keep the badge row on consecutive lines (no blank lines between badges). -->

<!-- AI: Badge — License (required): update SPDX identifier and link if not MIT -->
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
<!-- AI: Badge — npm version (required): replace {SCOPE}/{PACKAGE_NAME} with the full scoped or unscoped package name, e.g. @tsmx/json-tools or lodash -->
![npm version](https://img.shields.io/npm/v/{SCOPE}/{PACKAGE_NAME})
<!-- AI: Badge — Node.js version compatibility (required): same substitution as above -->
![node version](https://img.shields.io/node/v/{SCOPE}/{PACKAGE_NAME})
<!-- AI: Badge — CI build status (include when a GitHub Actions workflow exists): replace {GITHUB_USER}/{REPO_SLUG} and {WORKFLOW_FILE} accordingly -->
[![Build Status](https://img.shields.io/github/actions/workflow/status/{GITHUB_USER}/{REPO_SLUG}/{WORKFLOW_FILE}?branch=master)](https://img.shields.io/github/actions/workflow/status/{GITHUB_USER}/{REPO_SLUG}/{WORKFLOW_FILE}?branch=master)
<!-- AI: Badge — Test coverage via Coveralls (include when Coveralls is configured for the repo) -->
[![Coverage Status](https://coveralls.io/repos/github/{GITHUB_USER}/{REPO_SLUG}/badge.svg?branch=master)](https://coveralls.io/github/{GITHUB_USER}/{REPO_SLUG}?branch=master)

<!-- AI: H1 title — use the package name without scope prefix as display text.
     Link it to the GitHub repository when one exists (pattern: [**@{SCOPE}/{PACKAGE_NAME}**](https://github.com/...)).
     Drop the link when no public repository is available. -->
# [**@{SCOPE}/{PACKAGE_NAME}**](https://github.com/{GITHUB_USER}/{REPO_SLUG})

<!-- AI: Tagline — one concise sentence (max ~12 words) that captures WHAT the library does.
     Write it as a blockquote. No period at the end. -->
> {SHORT_TAGLINE}

---

## Description

<!-- AI: DESCRIPTION & BENEFITS SECTION
     Write 1–2 prose sentences that expand on the tagline: explain the primary problem solved
     and the main audience or context (e.g. "Ideal for pre-processing JSON in AI applications.").
     Then list the key capability groups as emoji-prefixed bullet clusters.
     Rules for the bullet list:
       - Group related functions under one emoji + linked heading anchor (e.g. [utility functions](#utility-functions)).
       - Each group heading links to its corresponding H3 subsection inside API Reference.
       - Under each group, add 2-4 sub-bullets naming the concrete capabilities.
       - Use a distinct emoji per group (🔍 analysis, 🔒 security/obfuscation, ⚡ transformation, ⚙️ config, 🗂️ file / data, etc.).
     End with an optional link line to companion tools, full docs, or an example project when they exist. -->

{DESCRIPTION_PARAGRAPH}

{EMOJI} [{CAPABILITY_GROUP_LABEL}](#{CAPABILITY_GROUP_ANCHOR})
- {capability 1}
- {capability 2}
- {capability 3}

{EMOJI} [{CAPABILITY_GROUP_LABEL}](#{CAPABILITY_GROUP_ANCHOR})
- {capability 1}
- {capability 2}

See the [API reference](#api-reference) for the full specs and examples.

<!-- AI: OPTIONAL companion-tool / docs link — remove if not applicable -->
> For advanced workflows see the [full documentation]({DOCS_URL}) or the [example project]({EXAMPLE_PROJECT_URL}).

---

## Usage

<!-- AI: USAGE SECTION
     Goal: let a developer understand the library in 30 seconds.
     Structure:
       1. (Optional) A motivating use-case block that shows a real-world scenario:
            - Show an INPUT data snippet (JSON, config file, object literal, etc.)
            - Show the 3-5 lines of code that use the library to solve the problem
            - Show the OUTPUT or resulting state
            - End with a one-line impact callout (token savings, security improvement, etc.)
          Wrap the entire use-case block in an HTML comment guard so it can be removed if not applicable.
       2. A minimal standalone code block (always required) — the simplest possible real usage,
          using CommonJS `require()` syntax by default.
          If the package explicitly supports ESM, add a second block with an `// ESM` comment header.
     Style: use inline `// Result: ...` comments inside code blocks instead of prose descriptions. -->

<!-- AI: OPTIONAL motivating use-case block — remove if there is no compelling before/after story -->
Suppose you have the following input:

```json
{
  "{KEY}": "{VALUE}"
}
```

To solve {PROBLEM}, simply do:

```javascript
const {IMPORT_NAME} = require('{SCOPE}/{PACKAGE_NAME}');

{MOTIVATING_CODE_EXAMPLE}
```

This gives you:

```
{MOTIVATING_OUTPUT}
```

> {IMPACT_CALLOUT}

<!-- END OPTIONAL motivating use-case block -->

### Basic Usage

```javascript
// CommonJS
const {IMPORT_NAME} = require('{SCOPE}/{PACKAGE_NAME}');

{BASIC_USAGE_CODE}
```

<!-- AI: OPTIONAL ESM usage block — include only when the package ships an ES module export -->
```javascript
// ESM
import {IMPORT_NAME} from '{SCOPE}/{PACKAGE_NAME}';

{BASIC_USAGE_CODE_ESM}
```
<!-- END OPTIONAL ESM block -->

---

## API Reference

<!-- AI: API REFERENCE SECTION — STRUCTURE RULES
     Hierarchy:
       H3  →  one per logical function group (e.g. "Obfuscation Functions", "Utility Functions").
               Format:  ### {Group Label} (`{moduleExport}`)
               The `{moduleExport}` in backticks is the JavaScript identifier used in require destructuring,
               e.g. `obfuscate`, `transform`. Omit it for top-level / default exports.
       H4  →  one per public function.
               Format:  #### `{export}.{functionName}(param1, param2, ...)`
               Use the exact call signature. Mark optional params with a trailing `?` or describe them in Parameters.
       Under each H4, always include IN THIS ORDER:
         1. One-sentence description of what the function does (no heading, just a paragraph).
         2. **Parameters:** — bullet list; each item: `name` (Type, optional): description. Default: `value`
            Omit "Default: ..." when the parameter is required with no default.
         3. **Returns:** — `Type` — brief description.
            OMIT the Returns line for functions that operate in-place / return void.
         4. **Example:** — a fenced ```javascript code block with:
              - realistic input variable(s) declared with `const`
              - the function call
              - output shown as `// Result: ...` inline comments or a multi-line comment block
     After the LAST H4 of each group, add a `---` horizontal rule to separate groups visually.
     Repeat the H3 + H4 pattern for every additional group.
     Comment at the top of this section reminds the skill to cover ALL exported functions. -->

<!-- AI: Document ALL exported/public functions of the library.
     Add one H3 group per logical namespace or capability cluster.
     Within each group, add one H4 entry per function following the pattern below. -->

### {GROUP_LABEL} (`{moduleExport}`)

<!-- AI: H3 GROUP INSTRUCTIONS
     Replace {GROUP_LABEL} with a human-readable label (e.g. "Obfuscation Functions", "Transformation Functions", "Utility Functions").
     Replace {moduleExport} with the JavaScript export name used in destructuring (e.g. obfuscate, transform).
     For a top-level / default export (no destructuring needed), omit the (`{moduleExport}`) part entirely. -->

#### `{moduleExport}.{functionName}(param1, param2)`

<!-- AI: Replace the H4 signature with the exact callable signature.
     Mark optional parameters with ? suffix in the signature (e.g. replacement?) or note them in the Parameters list. -->

{ONE_LINE_FUNCTION_DESCRIPTION}

**Parameters:**
- `param1` (Type): {description}
- `param2` (Type, optional): {description}. Default: `{defaultValue}`

**Returns:** `{ReturnType}` — {return description}

<!-- AI: OMIT the Returns line above for in-place / void functions -->

**Example:**
```javascript
const { {moduleExport} } = require('{SCOPE}/{PACKAGE_NAME}');

const input = {
  {EXAMPLE_INPUT_KEY}: '{EXAMPLE_INPUT_VALUE}'
};

{moduleExport}.{functionName}(input);
// Result: { {EXAMPLE_INPUT_KEY}: '{EXAMPLE_RESULT_VALUE}' }
```

#### `{moduleExport}.{functionName2}(param1)`

<!-- AI: Second function entry in this group — follow the exact same sub-structure as the entry above. -->

{ONE_LINE_FUNCTION_DESCRIPTION_2}

**Parameters:**
- `param1` (Type): {description}

**Returns:** `{ReturnType}` — {return description}

**Example:**
```javascript
const { {moduleExport} } = require('{SCOPE}/{PACKAGE_NAME}');

const input = {
  {EXAMPLE_INPUT_KEY}: '{EXAMPLE_INPUT_VALUE}'
};

const result = {moduleExport}.{functionName2}(input);
// Result: {EXAMPLE_RESULT_VALUE_2}
```

---

<!-- AI: Add more H3 + H4 blocks here, one H3 per additional function group.
     Keep the same sub-structure: description → Parameters → Returns (if applicable) → Example.
     End each group with a `---` horizontal rule. -->

<!-- ============================================================
     OPTIONAL SECTIONS
     Each block below is independently removable.
     Remove the entire block (including the comment guards) when the section does not apply.
     ============================================================ -->

<!-- OPTIONAL: INSTALLATION → REMOVE IF NOT APPLICABLE -->
## Installation

```bash
npm install {SCOPE}/{PACKAGE_NAME}
```

<!-- AI: Add a peer dependencies note when the library requires the consumer to install additional packages -->
<!-- AI: OPTIONAL peer deps note — remove if none -->
**Peer dependencies:** {PEER_DEPENDENCY_1}, {PEER_DEPENDENCY_2}
<!-- END OPTIONAL peer deps note -->

<!-- END OPTIONAL: INSTALLATION -->


<!-- OPTIONAL: CONFIGURATION / OPTIONS → REMOVE IF NOT APPLICABLE -->
## Options

<!-- AI: OPTIONS SECTION — use this section when the library/function accepts an options object.
     Show the full options object first as a code example, then document each option as an H3
     following the pattern: Type, Default, description, minimal code example.
     Mirror the pattern from @tsmx/secure-config: options object → one H3 per property. -->

To use the library with all defaults, call it without any arguments:

```javascript
const result = require('{SCOPE}/{PACKAGE_NAME}')();
```

To customize behavior, pass an options object:

```javascript
const options = {
  {OPTION_1}: {OPTION_1_EXAMPLE_VALUE},
  {OPTION_2}: {OPTION_2_EXAMPLE_VALUE}
};

const result = require('{SCOPE}/{PACKAGE_NAME}')(options);
```

### `{OPTION_1}`

Type: `{Type}`  
Default: `{defaultValue}`

{OPTION_1_DESCRIPTION}

```javascript
const options = { {OPTION_1}: {OPTION_1_EXAMPLE_VALUE} };
```

### `{OPTION_2}`

Type: `{Type}`  
Default: `{defaultValue}`

{OPTION_2_DESCRIPTION}

```javascript
const options = { {OPTION_2}: {OPTION_2_EXAMPLE_VALUE} };
```

<!-- AI: Add one H3 block per additional option following the same pattern. -->

<!-- END OPTIONAL: CONFIGURATION / OPTIONS -->


<!-- OPTIONAL: SETUP & INTEGRATION → REMOVE IF NOT APPLICABLE -->
## Setup

<!-- AI: SETUP SECTION — use for libraries that require environment variables, key generation,
     external tooling, or multi-step initialization before first use.
     Use a numbered list for ordered steps. Show shell commands and code blocks as appropriate.
     Mirror the pattern from @tsmx/secure-config: numbered steps with code blocks per step. -->

1. {SETUP_STEP_1}

   ```bash
   {SETUP_STEP_1_COMMAND}
   ```

2. {SETUP_STEP_2}

   ```javascript
   {SETUP_STEP_2_CODE}
   ```

3. {SETUP_STEP_3}

   ```bash
   {SETUP_STEP_3_COMMAND}
   ```

<!-- END OPTIONAL: SETUP & INTEGRATION -->


<!-- OPTIONAL: NAMING CONVENTIONS → REMOVE IF NOT APPLICABLE -->
## Naming Conventions

<!-- AI: NAMING CONVENTIONS SECTION — use when the library resolves file names, config names,
     or identifiers based on environment variables (e.g. NODE_ENV) or other runtime context.
     Show a table mapping environments → values → resulting file name,
     then a folder tree showing the expected project layout.
     Mirror the pattern from @tsmx/secure-config. -->

| Stage       | Value of `{ENV_VAR}` | Resulting name              |
|-------------|----------------------|-----------------------------|
| Development | not set              | `{DEFAULT_NAME}`            |
| Production  | `production`         | `{NAME_PATTERN}-production` |
| Test        | `test`               | `{NAME_PATTERN}-test`       |

Expected project layout:

```
{PROJECT_ROOT}/
├── {CONFIG_DIR}/
│   ├── {DEFAULT_NAME}
│   ├── {NAME_PATTERN}-production
│   └── {NAME_PATTERN}-test
├── app.js
└── package.json
```

<!-- END OPTIONAL: NAMING CONVENTIONS -->


<!-- OPTIONAL: MIGRATION / UPGRADING → REMOVE IF NOT APPLICABLE -->
## Upgrading from versions prior to {BREAKING_VERSION}

<!-- AI: MIGRATION SECTION — include when there is a breaking API change between major versions.
     Show the OLD usage, explain what changed, and show the NEW idiomatic usage.
     Keep it concise: old snippet → explanation sentence → new snippet. -->

In versions before `{BREAKING_VERSION}`, the library was used as follows:

```javascript
// {OLD_APPROACH_LABEL}
{OLD_USAGE_CODE}
```

Starting with `{BREAKING_VERSION}`, {MIGRATION_EXPLANATION}:

```javascript
// {NEW_APPROACH_LABEL}
{NEW_USAGE_CODE}
```

<!-- END OPTIONAL: MIGRATION / UPGRADING -->


<!-- OPTIONAL: SBOM → REMOVE IF NOT APPLICABLE -->
## SBOM

<!-- AI: SBOM SECTION — include when the package ships a CycloneDX (or SPDX) software bill of materials.
     One short sentence stating format version and file location is sufficient. -->

This package ships with a CycloneDX software bill of materials (SBOM) v{SBOM_VERSION} in {SBOM_FORMAT} format.
The file is located under the `{SBOM_DIR}/` folder.

<!-- END OPTIONAL: SBOM -->


<!-- OPTIONAL: CHANGELOG → REMOVE IF NOT APPLICABLE -->
## Changelog

<!-- AI: CHANGELOG SECTION — list versions in descending order (newest first).
     Each version is an H3. Under it, bullet-list the user-visible changes.
     Keep entries concise (one line each). Use past tense. -->

### {LATEST_VERSION}
- {CHANGE_1}
- {CHANGE_2}

### {PREVIOUS_VERSION}
- {CHANGE_1}

<!-- END OPTIONAL: CHANGELOG -->
