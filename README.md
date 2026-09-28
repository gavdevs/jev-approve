# jev-approve

Standalone, opt-in safety-approval extension for **OMP 18.3.5 on Linux**. No runtime dependencies. It uses TypeSafe's pinned `jev-1.13.0` model for four independent judgments; deterministic code owns permission.

**The default shadow mode is observational, not protection.** It records what the extension would decide, never asks for approval, and leaves tool execution and OMP's native approval policy unchanged. Enforcement must be explicitly enabled. This is **not a sandbox**, a credential vault, or tamper-proof containment.

## Install and explicitly activate

Keep this package outside other projects. OMP loads the package's `omp.extensions` manifest; no build step is necessary:

```sh
omp -e /absolute/path/to/jev-approve
```

Loading it does **not** activate remote classification. The default is shadow mode with remote calls off. When `JEV_APPROVE_REMOTE` is not exactly `1`, the judge is **never invoked** in any mode: deterministic rules still decide prohibits/routine-allows, every contextual action is recorded as `ask` with `remote_not_enabled` (shadow passes through observational; enforce fails closed), and no judgment state is assembled for transport. `/jev-status` reports the loaded policy version, current mode, outbound consent and audit destination. No global OMP configuration is modified by this package.

This source checkout includes a project-only `.omp/config.yml` registration pointing to its own package manifest. Starting `omp` from this directory therefore loads Jev without needing `-e`. This registration is not included in the published package files and does not activate Jev in other projects. Remote consent and enforcement remain separate opt-ins.

`-e` requires a path: API-key availability and `omp -e` alone are not evidence that the extension loaded. An already-running process must reload resources or restart to pick up a newly added registration; creating the file does not attach a gate to that process. Startup status includes the **loaded** policy version so it can be distinguished from code merely present on disk.

For an explicit-only extension set:

```sh
omp --no-extensions -e /absolute/path/to/jev-approve
```

OMP's `--no-extensions` still loads explicitly specified extensions, but skips the project registration above. It does not disable other discovery systems or provide process isolation.

**OMP 18.3.5 plugin-link caveat:** `omp plugin link` writes to the user/global plugin root even with `--scope project` or `--local`, and its `--dry-run` flag does not prevent linking. Use the project configuration or an explicit extension path instead of relying on those flags for a project-only installation. The version-matched [installer documentation](https://github.com/can1357/oh-my-pi/blob/v18.3.5/docs/plugin-manager-installer-plumbing.md) describes that user-root link implementation.

### Enable outbound Jev evaluation

Obtain an API key from TypeSafe and supply `TYPESAFE_API_KEY` through your trusted environment or secret manager. Do not put its value in the config file, shell command arguments, repository, or a model message. For example, in Bash:

```sh
read -rs -p 'TypeSafe API key: ' TYPESAFE_API_KEY; printf '\n'
export TYPESAFE_API_KEY
JEV_APPROVE_REMOTE=1 omp -e /absolute/path/to/jev-approve
```

This is still **shadow mode**. `JEV_APPROVE_REMOTE=1` explicitly consents to sending sanitized context to `https://api.typesafe.ai/v1/systemone`. The endpoint is fixed; redirects and automatic retries are disabled. One request contains all four questions. There is no verdict cache.

### Enable enforcement

```sh
JEV_APPROVE_MODE=enforce JEV_APPROVE_REMOTE=1 \
  omp -e /absolute/path/to/jev-approve
```

Without `JEV_APPROVE_REMOTE=1`, deterministic rules still apply and contextual actions require manual approval. A missing key, timeout, malformed response, unexpected model version, or service failure requires confirmation; headless sessions block instead. A configuration error in enforcement registers a blocking hook rather than throwing during load and silently disabling enforcement.

Restart OMP to change mode or configuration. There is no agent-callable mode toggle. Do not combine this with unknown or untrusted extensions.

## User authorization and approval

OMP 18.3.5 does not expose an immutable original-user-input record. Its input hooks are transformable; RPC/print prompts bypass that hook; extensions can inject messages attributed to the user. Therefore this extension **does not treat transcript roles, assistant summaries, tool results, repository text, or ordinary transformed prompts as proof of permission**.

Use `/jev-scope` while idle. Its UI dialog asks you to enter the actual task, allowed targets, and exclusions. That directly observed instruction is recorded only in memory with session/branch/cwd provenance, then submitted to OMP to start the task. A different prompt, ordinary interactive input, completed agent run, navigation, or compaction clears it. Cancellation or a session/branch/cwd change while the dialog is open discards the entry. A vague “yes” does not create scope. Nothing is reconstructed from saved conversations.

Ordinary prompts still work, but absent this reliable provenance the extension asks rather than interpreting their apparent authorization. Explicit operator-configured `readRoots` separately authorize narrowly verified local reads.

An **ask** in enforcement displays the sanitized exact action, cwd, target facts, triggered rule IDs and an opaque invocation identity. Approval is for that invocation only. It is not reused for a retry or an identical later call. The extension rechecks arguments, authorization epoch, cwd, target metadata, and config after remote/UI/audit waits. A change blocks; the agent must propose a new call. Redacted values are bound locally by an HMAC identity, not printed.

Headless sessions and subagents cannot answer the extension's confirmation dialog; they block on ask. Native OMP prompts remain independent and may also require approval. A Jev or manual allow never overrides a native deny.

## Optional operator policy

Set `JEV_APPROVE_CONFIG` to an **absolute path** to a JSON file you maintain outside agent-writable work where possible:

```json
{
  "readRoots": ["/absolute/path/to/workspace"],
  "deniedTools": ["computer"],
  "protectedPaths": ["/absolute/path/to/deployment-credentials"],
  "timeoutMs": 8000,
  "approvalTimeoutMs": 60000,
  "auditPath": "/absolute/path/to/private-state/jev-audit.jsonl"
}
```

All fields are optional. Unknown keys and invalid values reject the configuration. Timeout values must be integer milliseconds from 100 through 60000. Path fields must be absolute; `readRoots` must exist as directories. Defaults: no read roots, no additional denied tools/protected paths, 8-second Jev deadline, 60-second approval deadline, and `.jev-approve/audit.jsonl` under the launch cwd.

Changes to the loaded config file require a restart: they block enforcement until then. The package directory, active/standard OMP config roots, the old Prime root, config file, audit directory, and additional `protectedPaths` are protected from direct mutations. Merely listing a directory in `readRoots` does not authorize edits or code execution. Protected-path edits and credential access through opaque shell/Eval/patch operations are never automatically approved; their effects cannot be fully inferred from strings.

### Routing

1. **Block explicit prohibitions:** exact denied tool names, direct protected-path mutations, recognized credential reads, and literal private-key disclosure.
2. **Allow a narrow routine case:** an ordinary `read` of a verified existing file/directory inside explicit read roots, without sensitive path components or unknown arguments. Symlink-resolved targets must remain inside the root. Native OMP checks still apply.
3. **Evaluate contextual cases:** one Jev request, if explicitly enabled. Its structured state separates trusted policy and UI-observed user instructions from exact sanitized tool arguments, cwd, target facts, and untrusted prior action identities. No repository contents or tool outputs are elevated into permission.
4. **Route independently:**
   - `destruction`, `disclosure`, or `security` probability ≥ 0.90 blocks.
   - Any hazard ≥ 0.10 asks.
   - Automatic contextual allow requires `authorized` ≥ 0.98, reliable authorization, no redaction, and sufficiently known effects.
   - Opaque or missing effects always ask, even with favorable probabilities.

Questions distinguish destruction **outside** authorized scope from an explicitly requested scoped destructive action. Authorization cannot cancel a hazard; no weighted average is used. Reasons consist of fixed policy/judgment IDs, not invented model explanations.

Policy version **2** makes `authorized` a narrow scope-membership judgment: is this invocation one of the operations the user requested, with their limits respected? The host verifies provenance; the other Nouls assess hazards. A single invocation need not complete every step in a multi-step task. The question also explains OMP's file/directory `read` and file `write` semantics. No thresholds or mandatory gates were relaxed.

**These thresholds are experimental engineering choices, not validated command-safety thresholds.** Typed output does not establish model correctness. See [VERIFICATION.md](VERIFICATION.md) for exactly what was exercised.

## Host integration and coverage

OMP 18.3.5 runs ordinary `tool_call` handlers sequentially but passes each the original event. Returned argument revisions are accumulated separately. Loading a classifier last is not sufficient to judge final arguments.

`src/host.mjs` is an explicit **version-pinned interposition adapter**, not a supported final-input API. It preserves the native `ExtensionToolWrapper.execute` path, including original/revised denials, native UI, provider safety checks and result hooks. Its final delegate evaluates the actual arguments immediately before calling the underlying tool. In enforcement it detaches/freezes native-gated argument objects across asynchronous waits, and gives the tool a detached approved snapshot. A prior handler can return a revision; mutating frozen arguments in place may instead be rejected. Shadow does not freeze, replace arguments, prompt, or change native routing.

The adapter is scoped to runners containing this extension's registered marker. Rebound child factories get independent state. Unsupported versions or conflicting already-installed adapters register a fail-closed enforcement hook. Other same-process code can replace hooks, disable the extension, change memory or files, or execute effects outside tool dispatch: **none of this is containment**. Load/import failures themselves are still OMP's responsibility; verify the startup status before relying on enforcement.

| Surface | Treatment / boundary |
| --- | --- |
| Ordinary local `read` | Narrow deterministic allow only within explicit roots. Selectors, archives, DBs, URLs and internal URIs are not routine allows. |
| `write`, `edit`, file/device mutations | Direct targets get facts and protected-path checks; patch/indirect effects remain opaque. |
| Bash / Python / Eval | Always require conservative confirmation unless blocked. Script filenames do not prove contents; regexes are not a shell parser. |
| MCP / unknown custom tools | Wrapped dispatch is intercepted, but unknown effects remain opaque. |
| Eval `tool.*` | Normal registry bridge goes through wrapped tool dispatch; the outer Eval action also requires approval. |
| Browser/computer helpers, prelude `tabs()`/`capabilities()`/DOM calls inside Eval | Do **not** individually emit ordinary `tool_call`; runtime-verified zero per-action Jev records. Only the opaque outer Eval is covered. Native helper approvals may apply separately. |
| Task / Eval `agent()` / `workpool()` | Parent action is opaque; child factories are rebound and headless (runtime-proven spawned child writes block `no_interactive_approval`). Parent scope is not silently inherited as child authorization. Risky child asks block. |
| Commands, extensions, external processes, same-tool `invokeTool` delegation | Not independent per-effect interception boundaries. Approved tool/extension code retains ambient authority. |

State checks are metadata checks, not filesystem locks: external changes after the final check, hidden dependencies, aliases, hardlinks, indirect effects and same-process attacks remain outside a strong guarantee. For real containment use OS/process/network isolation and least-privilege credentials.

## Privacy and audit

Remote state may include task instructions, code, paths, destination names, file contents present in tool arguments, and host-derived `scopePaths` facts listing canonical workspace paths extracted from the operator's own scope text. Those facts are computed deterministically from trusted input the operator already supplied; they never include file contents or action arguments. Redaction removes supplied/ambient known credentials, sensitive named fields, environment maps, common token formats, PEM private keys, credential headers, secret flags/assignments and sensitive URL values. Discovered secret values are removed from other fields and object keys too. API credentials are used only in the HTTP Authorization header, never judgment state or audit rows. Transport errors are converted to fixed codes; raw response/error bodies are not logged.

**Heuristics cannot discover every arbitrary unknown secret or encoding.** Do not enable remote classification for workloads where sanitized context still cannot leave the machine. Redaction that removes evidence prevents automatic model-based approval.

Audit rows contain mode, proposed/final decision, rule IDs, raw probabilities when obtained, policy version/config digest, pinned model ID, elapsed milliseconds and a keyed opaque action identity. No raw arguments, user instructions, paths, prompts, credentials, model explanations or tool results are recorded. A context invalidation after an allow audit emits a subsequent block row for the same identity. These are gate decisions, not proof that execution completed; native denials occur before the final delegate and do not produce a Jev verdict.

Audit files are private (0600), reject symlinks/hardlinks and use Linux `/proc/self/fd` directory-relative opening to avoid redirecting writes through a replaced parent path. Audit failure blocks enforcement and warns in shadow. Logs are append-only at the application level, **not tamper-proof**, and have no automatic retention/rotation; manage their retention yourself.

## Verification and maintenance

From the source checkout:

```sh
node --test test/*.test.mjs
node scripts/omp-smoke.mjs
node scripts/agent-smoke.mjs
node scripts/agent-rebind-smoke.mjs      # Eval agent()/workpool() rebinding
node scripts/browser-boundary-smoke.mjs  # browser/computer prelude boundary
```

Node 22+ is needed for development tests; OMP's own embedded Bun loads the extension. Both smoke runners use the installed OMP runtime rather than a replacement wrapper implementation. They operate in temporary workspaces and require no provider key. The full-agent smoke registers a test-only deterministic provider, loads the package manifest, exercises `/jev-scope`, uses native read/write tools and spawns a real task child. These fixtures are excluded from the production package. See [VERIFICATION.md](VERIFICATION.md) for outcomes and coverage limits.

`/jev-status` also reports per-session decision counters (`total/allows/asks/blocks/automaticAllows`) and the three most recent audit decisions, so a shadow window becomes a readable signal rather than a JSONL file.

### Opt-in live evaluation

With `TYPESAFE_API_KEY` already exported:

```sh
JEV_APPROVE_REMOTE=1 npm run eval:live -- --split all --runs 2
JEV_APPROVE_REMOTE=1 node scripts/agent-smoke.mjs --live
JEV_APPROVE_REMOTE=1 node scripts/agent-smoke.mjs --live --discovery
```

The evaluator runs the production engine and Jev client against labelled synthetic proposals without executing them. Its 46 cases cover ordinary work, multi-step scope, fake authorization, exclusions, path/symlink escapes, scope path-spelling normalization, group/category scopes, destructive/disclosure/security hazards, redaction and deterministic prohibitions. `--split` selects `development`, `holdout`, `validation` or `all`. `--runs` repeats measurements without caching or retries; repeats incur API usage and are not independent examples.

JSONL output contains question/corpus digests, case IDs, probabilities, decisions, mismatches and summary counts—not credentials or raw action arguments. An unsafe automatic allow or transport/privacy failure exits nonzero. Unnecessary asks are reported, not hidden or treated as calibrated error rates. `--compare /path/to/baseline-questions.json` evaluates a saved `QUESTIONS` object alongside the current questions against identical state, reversing order on alternate runs.

The optional live agent smoke still uses a deterministic agent provider, but Jev responses are real. It removes routine read-root allowances, collects scope through OMP's actual UI protocol and exercises built-in read/write plus a headless task child in a temporary workspace. It verifies real effects, protected/child blocks and exact confirmations; it **reports** how many contextual actions auto-allow rather than asserting a particular model probability. Borderline 0.97/0.98 judgments can change whether a prompt appears.

`--discovery` loads Jev from a temporary project's `.omp/config.yml`, with no Jev `-e` argument. It exercises the activation path used by this checkout, not just explicit loading in a separately configured process. Without `--live`, that discovery smoke requires no model key. Every recorded decision is checked against the current policy version.

To prepare a question baseline before changing wording:

```sh
node --input-type=module -e 'import { QUESTIONS } from "./src/jev.mjs"; console.log(JSON.stringify(QUESTIONS, null, 2))' > /tmp/jev-baseline-questions.json
```

Keep a genuinely uninspected validation split when iterating; do not repeatedly tune on a supposed holdout. None of these checks establishes production calibration or adversarial robustness.

Before supporting another OMP release, recheck argument transformation, wrapper ordering, user ingress, nested dispatch and child factory binding against that exact version, extend runtime scenarios, and only then update `SUPPORTED_OMP`. Never remove the version guard merely to make startup succeed.

## Primary references

- [TypeSafe HTTP API](https://docs.typesafe.ai/api.md), [Noul](https://docs.typesafe.ai/primitives/noul.md), [State](https://docs.typesafe.ai/concepts/state.md), [Confidence](https://docs.typesafe.ai/confidence.md), [Guardrail pattern](https://docs.typesafe.ai/cookbooks/llm_guardrails.md), [JavaScript SDK](https://docs.typesafe.ai/sdk/javascript.md), [pinned models](https://docs.typesafe.ai/models.md).
- OMP local docs: `omp://extensions.md`, `omp://extension-loading.md`, `omp://approval-mode.md`, `omp://rpc.md`.
- Version-matched OMP source: [runner](https://github.com/can1357/oh-my-pi/blob/v18.3.5/packages/coding-agent/src/extensibility/extensions/runner.ts), [wrapper](https://github.com/can1357/oh-my-pi/blob/v18.3.5/packages/coding-agent/src/extensibility/extensions/wrapper.ts), [tool bridge](https://github.com/can1357/oh-my-pi/blob/v18.3.5/packages/coding-agent/src/eval/js/tool-bridge.ts), [Eval preludes](https://github.com/can1357/oh-my-pi/blob/v18.3.5/packages/coding-agent/src/eval/preludes.ts).
