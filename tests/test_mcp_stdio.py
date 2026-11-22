"""Prove an actual MCP STDIO handshake and advertised tool catalogue.

No PostgreSQL or Docker is required for tools/list.
"""
import asyncio
import sys
import unittest
from pathlib import Path

from mcp import Client, StdioServerParameters

SERVER = Path(__file__).resolve().parents[1] / "integrations/mcp/appsec_mcp.py"


class MCPStdioHandshakeTests(unittest.IsolatedAsyncioTestCase):
    async def test_tools_discovery_over_stdio(self):
        async def probe():
            params = StdioServerParameters(
                command=sys.executable,
                args=[str(SERVER), "--transport", "stdio"],
            )
            async with Client(params) as client:
                response = await client.list_tools()
                entries = response.tools if hasattr(response, "tools") else response
                names = {tool.name for tool in entries}
                self.assertIn("get_security_overview", names)
                self.assertIn("list_pipelines", names)
                self.assertIn("get_secret_findings", names)
                self.assertNotIn("run_scan", names)
                self.assertNotIn("execute_shell", names)

        await asyncio.wait_for(probe(), timeout=30)


if __name__ == "__main__":
    unittest.main()
