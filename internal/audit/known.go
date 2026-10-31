package audit

// knownPackages are widely used MCP server packages and images. A launch
// target that is a near-miss of one of these (but not an exact match) is
// reported as a possible typosquat. Extend this list freely.
var knownPackages = []string{
	// Reference servers
	"@modelcontextprotocol/server-filesystem",
	"@modelcontextprotocol/server-github",
	"@modelcontextprotocol/server-gitlab",
	"@modelcontextprotocol/server-postgres",
	"@modelcontextprotocol/server-memory",
	"@modelcontextprotocol/server-everything",
	"@modelcontextprotocol/server-sequential-thinking",
	"@modelcontextprotocol/server-puppeteer",
	"@modelcontextprotocol/server-brave-search",
	"@modelcontextprotocol/server-slack",
	"@modelcontextprotocol/server-gdrive",
	"@modelcontextprotocol/server-google-maps",
	"@modelcontextprotocol/server-redis",
	"@modelcontextprotocol/inspector",
	"mcp-server-fetch",
	"mcp-server-git",
	"mcp-server-time",
	"mcp-server-sqlite",
	// Popular vendor / community servers
	"@playwright/mcp",
	"@upstash/context7-mcp",
	"@notionhq/notion-mcp-server",
	"@supabase/mcp-server-supabase",
	"@stripe/mcp",
	"@sentry/mcp-server",
	"@cloudflare/mcp-server-cloudflare",
	"@browserbasehq/mcp-server-browserbase",
	"@executeautomation/playwright-mcp-server",
	"@wonderwhy-er/desktop-commander",
	"@heroku/mcp-server",
	"@21st-dev/magic",
	"chrome-devtools-mcp",
	"mcp-remote",
	"figma-developer-mcp",
	"firecrawl-mcp",
	"exa-mcp-server",
	"tavily-mcp",
	// Container images
	"ghcr.io/github/github-mcp-server",
	"mcp/github",
	"mcp/fetch",
	"mcp/filesystem",
	"mcp/postgres",
	"mcp/memory",
}

// nearestKnown returns a known package that name is suspiciously close to.
func nearestKnown(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	for _, k := range knownPackages {
		if k == name {
			return "", false
		}
	}
	best, bestD := "", 1<<30
	for _, k := range knownPackages {
		if d := levenshtein(name, k); d < bestD {
			best, bestD = k, d
		}
	}
	limit := 1
	if len(best) > 10 {
		limit = 2
	}
	if bestD > 0 && bestD <= limit {
		return best, true
	}
	return "", false
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}
