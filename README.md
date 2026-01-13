# CrowdStrike AIDR MCP proxy

Protect communications between a client and any MCP server. Now with 99% less
prompt injection! The CrowdStrike AIDR MCP proxy allows any MCP client to secure
the messages it sends and receives to/from an MCP server, using the CrowdStrike
AIDR service to guard tools' inputs and outputs.

What it does: protect users from common threat vectors by running all MCP I/O
through CrowdStrike AIDR, which blocks:

- Prompt injections (yes, even the ones wrapped in a riddle)
- Malicious links, IPs, domains
- 50 types of confidential information and PII
- 10 content filters, including toxicity, self harm, violence, and filtering by topic
- Support for 104 spoken languages

## Prerequisites

- Node.js v22.15.0 or greater.
- A CrowdStrike AIDR API token.

## Usage

In an existing stdio-based MCP server configuration like the following:

```json
{
  "mcpServers": {
    "qrcode": {
      "command": "npx",
      "args": ["-y", "@jwalsh/mcp-server-qrcode"]
    }
  }
}
```

Wrap the original command with `npx -y @crowdstrike/aidr-mcp-proxy` and add
environment variables:

```json
{
  "mcpServers": {
    "qrcode": {
      "command": "npx",
      "args": [
        "-y",
        "@crowdstrike/aidr-mcp-proxy",
        "--",
        "npx",
        "-y",
        "@jwalsh/mcp-server-qrcode"
      ],
      "env": {
        "CS_AIDR_TOKEN": "cs_00000000000000000000000000000000",
        "CS_AIDR_BASE_URL_TEMPLATE": "https://api.crowdstrike.com/aidr/{SERVICE_NAME}"
      }
    }
  }
}
```

1. Update the `CS_AIDR_TOKEN` value to the CrowdStrike AIDR API token.
1. Update the `CS_AIDR_BASE_URL_TEMPLATE` value to the CrowdStrike AIDR base URL
   template.

For remote servers using HTTP or SSE, use [mcp-remote][] to turn them into stdio
servers:

```json
{
  "mcpServers": {
    "proxied": {
      "command": "npx",
      "args": [
        "-y",
        "@crowdstrike/aidr-mcp-proxy",
        "--",
        "npx",
        "-y",
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "CS_AIDR_TOKEN": "cs_00000000000000000000000000000000",
        "CS_AIDR_BASE_URL_TEMPLATE": "https://api.crowdstrike.com/aidr/{SERVICE_NAME}"
      }
    }
  }
}
```

### App ID

To identify the calling app by ID in CrowdStrike AIDR, set the `APP_ID`
environment variable.

### App name

To identify the calling app by name in CrowdStrike AIDR, set the `APP_NAME`
environment variable.

[mcp-remote]: https://github.com/geelen/mcp-remote
