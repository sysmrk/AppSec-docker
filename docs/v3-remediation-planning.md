# v3 Phase 2 — deterministic remediation planning

Development only. The v2 approval, patch and publication execution paths remain unchanged. No new backend execution is enabled by this phase.

The plan groups all scanner findings by package, normalized target and ecosystem, preserves scanner-reported versions and prioritizes Critical / High / Unknown / Medium / Low. Mixed installation versions or inconsistent inventory require manual review. Known fix does not mean available or compatible.

Strategies: targeted OS (existing guarded workflow), comprehensive OS (experimental candidate), Python/npm in-image (experimental candidate), source rebuild, base image review, advisory review, manual review. The first option is a deterministic suggested route, not a verified dependency solution. Source rebuild remains preferred for library dependencies. Upstream supports comprehensive updates and experimental library patching, but application helper mappings and package-manager compatibility require separate validation:
- https://project-copacetic.github.io/copacetic/website/introduction
- https://project-copacetic.github.io/copacetic/website/v0.13.x/app-level-patching
- https://project-copacetic.github.io/copacetic/website/troubleshooting

## Interfaces

Review remediation plan from a completed guided workflow, or read the Suggested next actions section in HTML. API GET /api/remediation/{pipeline_id}/plan?stage=original&offset=0&limit=25 (max 100 groups per page). residual stage requires a verified linked rescan. The complete plan digest is stable across pages. The API is authenticated; normal project authorization applies, and nonadmins can access unassigned manual workflows only as creator (unassigned legacy pipelines are admin-only).

POST /api/remediation/{pipeline_id}/validate accepts exactly stage, plan_digest and selections (1–100 entries with action_id and strategy only). It recomputes the evidence-bound plan and rejects stale/unknown/duplicate/disallowed input. Validation returns execution_authorized=false and package_compatibility_verified=false. No shell, versions, arbitrary URLs, commands or approval fields are accepted. No database state is written.

Optional MCP exposes the same two interfaces using a dedicated Viewer key. Existing global SQL analytics must be explicitly configured and must not be enabled for a project-scoped client. See [MCP](mcp.md). This is a tool interface for an external AI client, not an integrated LLM provider. The platform does not send findings to any external AI service automatically.

Next: isolate and benchmark comprehensive OS candidate generation; verify native package availability and version semantics; evaluate experimental Python/npm helper paths without bypassing approved source mappings. Only promote a candidate after independent frozen-DB comparison, compatibility tests and human approval. Preserve the deterministic plan contract for the Go migration.

The initial isolated candidate generation CLI is now available: [Remediation lab](v3-remediation-lab.md). It is not connected to the planner or publication workflow. Actual candidate coverage and functionality are not yet measured.

Experimental Python/npm candidate generation is now implemented in the isolated lab. Its eligibility filter is deliberately narrower than the planning classification; the planner does not authorize or predict successful execution. See [lab](v3-remediation-lab.md).

## Local AI provider (optional)

The host-side assistant supports an already installed local Ollama model through the fixed loopback HTTP endpoint. It reads an exported full pipeline summary (see [research](v3-remediation-research.md)), builds the deterministic plan, and sends at most 25 sanitized package groups per request. Only package names, ecosystem, bounded CVE/version tokens, severity counts and allowed strategy IDs are sent. No repository URL, image reference, paths, raw report, credentials or environment variables are sent. No remote provider, model download, proxy or redirect is supported. Ensure the Ollama service really is local and authorized; it may retain prompts or have its own external configuration.

    PYTHONPATH=../AppSec-v3/runner python3 -m appsecctl.ai_assist \\
      --summary pipeline-summary.json --model YOUR_LOCAL_MODEL \\
      --stage original --confirm-local-ai > ai-advice.json

Use --offset to review further groups, or --stage residual for linked verified rescans. The response accepts only action_id, an allowlisted strategy and a fixed reason code. The planner rejects unknown, duplicate, out-of-batch or disallowed selections. Model-generated prose, commands, package versions, metrics and approval fields are rejected. Output is a separate JSON advisory; it cannot modify scans, build images or authorize publication. This is an initial provider adapter, not automatic integration into the UI or MCP client transport. The existing scoped MCP endpoints remain available for independent external AI clients. Real-model performance is unverified.
