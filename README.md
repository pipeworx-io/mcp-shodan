# mcp-shodan

Shodan MCP — wraps the full Shodan REST API (api.shodan.io)

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1394+ live data sources.

## Tools

| Tool | Description |
|------|-------------|
| `shodan_host` | What's exposed on IP <ip> — open ports, services, and CVEs. Returns the full Shodan host profile: ports, hostnames, org/ISP, geolocation, OS, known vulnerabilities, and a per-service banner sample. Example: shodan_host({ ip: "8.8.8.8", _apiKey: "your-key" }) |
| `shodan_host_search` | Search Shodan for hosts matching <query> using Shodan search syntax (e.g. "apache country:US", "port:22 org:\"Google\""). Returns matching hosts with IP, port, org, hostnames, product, and location. Example: shodan_host_search({ query: "apache country:US", _apiKey: "your-key" }) |
| `shodan_host_count` | Count hosts matching <query> with facet breakdown (free — this endpoint does not consume query credits). Returns the total match count plus optional facet aggregations (e.g. top countries, orgs, ports). Example: shodan_host_count({ query: "apache", facets: "country:10", _apiKey: "your-key" }) |

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "shodan": {
      "url": "https://gateway.pipeworx.io/shodan/mcp"
    }
  }
}
```

Or connect to the full Pipeworx gateway for access to all 1394+ data sources:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English:

```
ask_pipeworx({ question: "your question about Shodan data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
