interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * Shodan MCP — wraps the full Shodan REST API (api.shodan.io)
 *
 * This is the PAID full-API pack (BYO key). Distinct from the free keyless
 * `shodan-internetdb` pack — this one exposes the host lookup, search, and
 * count endpoints that require a paid Shodan membership ($49 one-time).
 *
 * Tools:
 * - shodan_host: full host profile for an IP (open ports, services, CVEs)
 * - shodan_host_search: search hosts with Shodan query syntax
 * - shodan_host_count: count + facet breakdown for a query (free, no query credits)
 *
 * Requires API key via _apiKey parameter (passed as `key` query param).
 */


const BASE_URL = 'https://api.shodan.io';

const tools: McpToolExport['tools'] = [
  {
    name: 'shodan_host',
    description:
      "What's exposed on IP <ip> — open ports, services, and CVEs. Returns the full Shodan host profile: ports, hostnames, org/ISP, geolocation, OS, known vulnerabilities, and a per-service banner sample. Example: shodan_host({ ip: \"8.8.8.8\", _apiKey: \"your-key\" })",
    inputSchema: {
      type: 'object',
      properties: {
        ip: {
          type: 'string',
          description: 'IPv4 address to look up, e.g. "8.8.8.8"',
        },
        history: {
          type: 'boolean',
          description: 'Include historical banners (optional, default false)',
        },
        _apiKey: {
          type: 'string',
          description: 'Shodan API key (account.shodan.io; paid membership required)',
        },
      },
      required: ['ip', '_apiKey'],
    },
  },
  {
    name: 'shodan_host_search',
    description:
      'Search Shodan for hosts matching <query> using Shodan search syntax (e.g. "apache country:US", "port:22 org:\\"Google\\""). Returns matching hosts with IP, port, org, hostnames, product, and location. Example: shodan_host_search({ query: "apache country:US", _apiKey: "your-key" })',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description:
            'Shodan search query. Supports filters like country:, org:, port:, product:, os:, e.g. "apache country:US"',
        },
        page: {
          type: 'integer',
          description: 'Result page number (optional, 100 results/page, default 1)',
        },
        _apiKey: {
          type: 'string',
          description: 'Shodan API key (account.shodan.io; paid membership required)',
        },
      },
      required: ['query', '_apiKey'],
    },
  },
  {
    name: 'shodan_host_count',
    description:
      'Count hosts matching <query> with facet breakdown (free — this endpoint does not consume query credits). Returns the total match count plus optional facet aggregations (e.g. top countries, orgs, ports). Example: shodan_host_count({ query: "apache", facets: "country:10", _apiKey: "your-key" })',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Shodan search query, e.g. "apache" or "port:443 country:DE"',
        },
        facets: {
          type: 'string',
          description:
            'Comma-separated facets for aggregation, e.g. "country:10" or "org:5,port:5" (optional)',
        },
        _apiKey: {
          type: 'string',
          description: 'Shodan API key (account.shodan.io; paid membership required)',
        },
      },
      required: ['query', '_apiKey'],
    },
  },
];

// Shared GET helper. Appends the API key + params, then maps Shodan's error
// shapes to actionable messages (401 = bad/missing paid key; other non-2xx
// surface the JSON {error} body when present).
async function shodanGet(
  path: string,
  params: Record<string, string>,
  apiKey: string,
  tool: string,
): Promise<any> {
  const search = new URLSearchParams({ key: apiKey, ...params });
  const res = await fetch(`${BASE_URL}${path}?${search}`);

  if (res.status === 401) {
    throw new Error(
      `Shodan ${tool}: unauthorized (HTTP 401) — check your Shodan _apiKey (paid membership required). Get one at account.shodan.io.`,
    );
  }
  if (!res.ok) {
    let msg: string | undefined;
    try {
      const body = (await res.json()) as { error?: string };
      msg = body?.error;
    } catch {
      // non-JSON body
    }
    if (msg) throw new Error(`Shodan ${tool}: ${msg}`);
    throw new Error(`Shodan ${tool} error: HTTP ${res.status}`);
  }

  return res.json();
}

function requireApiKey(apiKey: string | undefined): string {
  if (!apiKey) {
    throw new Error(
      'Shodan requires an API key — pass your Shodan API key via _apiKey. Get one at account.shodan.io ($49 one-time membership).',
    );
  }
  return apiKey;
}

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const apiKey = requireApiKey(args._apiKey as string | undefined);
  delete args._apiKey;

  switch (name) {
    case 'shodan_host':
      return shodanHost(args.ip as string, args.history as boolean | undefined, apiKey);
    case 'shodan_host_search':
      return shodanHostSearch(args.query as string, args.page as number | undefined, apiKey);
    case 'shodan_host_count':
      return shodanHostCount(args.query as string, args.facets as string | undefined, apiKey);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

interface ShodanService {
  port?: number;
  transport?: string;
  product?: string;
  version?: string;
  data?: string;
}

interface ShodanHostResponse {
  ip_str?: string;
  ports?: number[];
  hostnames?: string[];
  org?: string;
  isp?: string;
  country_name?: string;
  city?: string;
  os?: string | null;
  vulns?: string[];
  data?: ShodanService[];
}

async function shodanHost(ip: string, history: boolean | undefined, apiKey: string) {
  if (!ip) {
    throw new Error('Shodan shodan_host requires an `ip` (e.g. "8.8.8.8").');
  }
  const params: Record<string, string> = {};
  if (history) params.history = 'true';

  const data = (await shodanGet(
    `/shodan/host/${encodeURIComponent(ip)}`,
    params,
    apiKey,
    'shodan_host',
  )) as ShodanHostResponse;

  const services = (data.data ?? []).slice(0, 30).map((s) => ({
    port: s.port,
    transport: s.transport,
    product: s.product,
    version: s.version,
    banner: typeof s.data === 'string' ? s.data.slice(0, 200) : undefined,
  }));

  return {
    ip: data.ip_str,
    ports: data.ports,
    hostnames: data.hostnames,
    org: data.org,
    isp: data.isp,
    country: data.country_name,
    city: data.city,
    os: data.os,
    vulns: data.vulns,
    services,
  };
}

interface ShodanMatch {
  ip_str?: string;
  port?: number;
  org?: string;
  hostnames?: string[];
  product?: string;
  location?: { country_name?: string; city?: string };
}

interface ShodanSearchResponse {
  total?: number;
  matches?: ShodanMatch[];
}

async function shodanHostSearch(query: string, page: number | undefined, apiKey: string) {
  if (!query) {
    throw new Error(
      'Shodan shodan_host_search requires a `query` in Shodan search syntax (e.g. "apache country:US").',
    );
  }
  const params: Record<string, string> = { query };
  if (page !== undefined) params.page = String(page);

  const data = (await shodanGet(
    '/shodan/host/search',
    params,
    apiKey,
    'shodan_host_search',
  )) as ShodanSearchResponse;

  return {
    total: data.total,
    matches: (data.matches ?? []).slice(0, 50).map((m) => ({
      ip: m.ip_str,
      port: m.port,
      org: m.org,
      hostnames: m.hostnames,
      product: m.product,
      location: {
        country: m.location?.country_name,
        city: m.location?.city,
      },
    })),
  };
}

interface ShodanCountResponse {
  total?: number;
  facets?: Record<string, Array<{ value: string; count: number }>>;
}

async function shodanHostCount(query: string, facets: string | undefined, apiKey: string) {
  if (!query) {
    throw new Error(
      'Shodan shodan_host_count requires a `query` in Shodan search syntax (e.g. "apache").',
    );
  }
  const params: Record<string, string> = { query };
  if (facets) params.facets = facets;

  const data = (await shodanGet(
    '/shodan/host/count',
    params,
    apiKey,
    'shodan_host_count',
  )) as ShodanCountResponse;

  return {
    total: data.total,
    facets: data.facets,
  };
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;
