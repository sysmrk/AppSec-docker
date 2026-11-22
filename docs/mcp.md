# Optional AppSec MCP Server — setup, AI connection and results

This integration is **opt-in**, **read-only**, and entirely separate from the existing AppSec API / worker. Default `make init`, `make up`, `docker compose --profile platform up` and production profiles do **not** start MCP. It does not require an LLM account or key to run: an AI MCP **client** is a separate application.

## 1. What it exposes

MCP tools (no mutation / scan / patch / push / shell execution):

| Tool | Input | Example result |
| --- | --- | --- |
| `get_security_overview` | none | Pipeline state totals, scan severity totals, secret-scan aggregate |
| `list_pipelines` | `limit` | Array of recent image and pipeline IDs/status |
| `get_pipeline` | `pipeline_id` UUID | Pipeline and original/patched scan IDs/counts |
| `list_image_vulnerabilities` | `pipeline_id`, optional `phase`, `limit` | CVEs, packages, installed/fixed versions |
| `list_secret_scan_jobs` | optional `limit` | Secret scan job summary |
| `get_secret_findings` | `job_id`, optional `limit` | Rule, severity and file/line; **never secret value or evidence** |
| `get_policy_results` | `pipeline_id`, `limit` | Policy pass/fail + violations |

Responses are JSON-compatible. Each query is a bounded, parameterized `SELECT`. The Python/PostgreSQL session sets `default_transaction_read_only=on` as a defense in depth. MCP tools operate over the existing database, so if no scans have run, their output is empty; MCP does not create scans for you.

**Data access warning:** MCP is a global security analytics view; it does not impersonate AppSec users or enforce the web API's per-project RBAC. Give it access only to administrators or a dedicated approved security AI account, with a dedicated SELECT-only database role. Never expose the HTTP port to the Internet directly.

## 2. Start AppSec normally (MCP is OFF)

```bash
./appsec setup
./appsec start
./appsec doctor
docker compose -f docker-compose.yaml ps
```

The existing platform works without MCP. Ensure the database has been initialized and migrated first:

```bash
./scripts/appsecctl.sh migrate
```

## 3. Enable MCP explicitly

```bash
make mcp-up
docker compose -f docker-compose.yaml --profile mcp ps mcp
make mcp-logs
```

This starts an independent service using the `mcp` Compose profile. The HTTP transport is Streamable HTTP (stateless JSON mode), bound only to the **local host**:

```text
http://127.0.0.1:8091/mcp
```

Override the local port with `APPSEC_MCP_HOST_PORT` in `.env`. Do not use `curl /mcp` as a health check: MCP requires protocol messages/headers; use the MCP Inspector or a compatible MCP client.

Stop only MCP, leaving the rest of AppSec running:

```bash
make mcp-down
```

Run normal AppSec without MCP: `./appsec start`. Simply having the MCP source code, Dockerfile or extra configuration does not activate it.

## 4. Security: use a read-only PostgreSQL account in production

Default Compose DB credentials are only a developer convenience. Do not expose a production MCP service using the application's write-capable Postgres login. As a database administrator, create a role with only the needed `SELECT` permissions:

```sql
CREATE ROLE appsec_mcp LOGIN PASSWORD 'REPLACE_WITH_RANDOM_PASSWORD';
GRANT CONNECT ON DATABASE appsec TO appsec_mcp;
GRANT USAGE ON SCHEMA public TO appsec_mcp;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO appsec_mcp;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO appsec_mcp;
```

In `.env` (URL-encode special characters in the password):

```dotenv
APPSEC_MCP_DATABASE_URL=postgresql://appsec_mcp:URL_ENCODED_PASSWORD@postgres:5432/appsec
APPSEC_MCP_HOST_PORT=8091
```

Keep this file out of Git. Production should use a Docker/Kubernetes secret solution rather than an environment variable where supported. The MCP container has no Docker socket, no report volume, no privileged mode, no Linux capabilities and a read-only filesystem. The local HTTP port does **not** implement OAuth or API-key authorization: its only ingress safety boundary is the loopback binding. Externalize it only through a TLS termination and proper identity-aware OAuth 2.0 gateway with per-user access policy, or use the local STDIO option below.

## 5. Connect a local AI — Claude Desktop via STDIO

This option avoids exposing any MCP HTTP listener. Prerequisites: Docker Engine + Compose v2, AppSec initialized, Claude Desktop on the same machine, and permission to launch Docker. In Claude Desktop's local MCP server configuration, add the following (adjust the `--project-directory` path):

```json
{
  "mcpServers": {
    "appsec-readonly": {
      "command": "docker",
      "args": [
        "compose",
        "--project-directory", "/absolute/path/to/AppSec-docker",
        "-f", "/absolute/path/to/AppSec-docker/docker-compose.yaml",
        "--profile", "mcp",
        "run", "--rm", "-T", "mcp",
        "--transport", "stdio"
      ]
    }
  }
}
```

On Windows, use the full Windows repository path, for example `C:\\Projects\\AppSec-docker` in both locations (double backslashes inside JSON), and verify `docker compose` works in a PowerShell terminal. Restart Claude Desktop / reload MCP tools. This starts an ephemeral container for the AI tool connection and does **not** launch the HTTP MCP service. The Postgres container and database must be accessible.

Ask the AI:

> Use the appsec-readonly tools to list the 5 most recent pipelines. For the latest pipeline show original vs patched CVEs, high/critical counts, and the policy result. Cite the returned pipeline IDs; do not fabricate missing results.

**Expected outputs:** the client shows the tools `list_pipelines`, `get_pipeline`, etc.; tool results contain structured IDs, status and counts; the assistant then summarizes them. Results with `{"pipelines":[]}` mean there are no records yet, not that the connector failed.

## 6. Inspect HTTP MCP tools and read raw outputs

On the server machine:

```bash
make mcp-up
npx @modelcontextprotocol/inspector
```

In the Inspector UI select **Streamable HTTP** transport and enter `http://127.0.0.1:8091/mcp`. Click **Connect**, then **Tools → List Tools**, select e.g. `get_security_overview` or `list_pipelines`, and click **Run Tool**. The structured response appears in the Inspector results pane.

Without a UI you can also use a Python MCP v2 client (install `pip install mcp==2.2.0` in your own venv):

```python
import asyncio
from mcp import Client

async def main():
    async with Client("http://127.0.0.1:8091/mcp") as client:
        tools = await client.list_tools()
        print([tool.name for tool in tools])
        result = await client.call_tool("get_security_overview", {})
        print(result)

asyncio.run(main())
```

If a client API changes in a later MCP SDK release, pin to the tested major version and consult the official SDK documentation.

## 7. ChatGPT, hosted Claude and other remote AI services

A hosted AI service cannot connect to `127.0.0.1` of your PC/server. It needs an endpoint reachable **from its cloud service**. Do not publish `:8091/mcp` directly. First deploy an HTTPS reverse proxy with OAuth 2.0 resource-server functionality and policy-enforced authorization in front of an isolated MCP service. Ensure the AI client supports remote MCP and the gateway's authorization flow. Then configure its custom MCP connector using your approved `https://mcp.example.org/mcp` URL. Exact menus and eligibility vary by AI product/account.

For environments without publicly accessible OAuth MCP infrastructure, **use the local STDIO client**. A local model via an MCP-capable desktop client also works; MCP doesn't require sending findings to any vendor until you connect an AI that transmits prompts/tool results to its service.

## 8. Where outputs are stored / viewed

MCP **reads existing data**; it does not persist an AI conversation or create an AppSec report:
- AI client: the model's response and tool invocation/results (subject to that product's logging/data policies).
- MCP Inspector: the raw JSON for each called tool.
- AppSec: original scan/pipeline/security job outputs remain in Postgres, Grafana, Metabase and authorized AppSec API endpoints.
- AppSec Control Center: `http://127.0.0.1:8080`; Grafana: `http://127.0.0.1:8080/grafana/`; Metabase: `http://127.0.0.1:3001` when started with `./appsec start --analytics`.
- AppSec API: `curl -H "X-API-Key: <KEY>" http://127.0.0.1:8080/appsec-api/pipelines/<PIPELINE_UUID>`.
- Logs: `make mcp-logs` for HTTP MCP service.

Never paste production credentials into AI prompts. Do not enable unrestricted secret report exports or write tools. Keep authorization and audit logs at the AI gateway for remote usage.

## 9. Troubleshooting

| Symptom | Verify |
| --- | --- |
| MCP tools missing | Confirm profile `mcp`, inspect Docker logs and client STDIO command |
| Database authentication failed | `APPSEC_MCP_DATABASE_URL` value, role/password and Postgres reachability |
| No pipelines | Run a normal AppSec scan first (MCP is deliberately read-only) |
| HTTP connection refused | `make mcp-up`, port 8091 bound on server localhost, no container failures |
| Remote AI cannot reach localhost | Use local STDIO or deploy a properly authenticated HTTPS MCP gateway |
| Unauthorized SQL query | Ensure SELECT grants to `appsec_mcp`; do not grant write rights |
| Unexpected secret exposure | Stop service and check legacy DB/files/S3/backup cleanup; rotate secrets |

## 10. Operator acceptance checklist

- [ ] MCP absent from normal `make up` / production profile
- [ ] Read-only MCP SQL account in use
- [ ] No outbound external access to the MCP port; loopback only
- [ ] Inspector lists tools and returns data from real completed scans
- [ ] Mutating commands / arbitrary SQL are not exposed as tools
- [ ] Secret values never appear in tool payloads
- [ ] Historical credentials rotated and old report artifacts purged
- [ ] External gateways enforce OAuth + TLS and produce audit logs


## Control Center vs MCP

The Control Center is a real, authenticated, Project-aware browser interface for scan-only jobs, vulnerabilities and report downloads. MCP remains an optional read-only analytics integration; it creates no scans, enables no patching, and returns empty results until real scans run. See [user guide](user-guide.md).
