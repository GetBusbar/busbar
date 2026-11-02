# Point Claude Code at Busbar. The only real "integration" — one base URL.
export ANTHROPIC_BASE_URL="http://127.0.0.1:8080/claude-code"   # the one that redirects it
: "${BUSBAR_AGENT_TOKEN:?Mint a virtual key through the admin API first (see README.md)}"
export ANTHROPIC_API_KEY="$BUSBAR_AGENT_TOKEN"
export CLAUDE_CODE_MAX_OUTPUT_TOKENS=4096       # Nova needs an explicit output cap
export DISABLE_PROMPT_CACHING=1                 # Nova has no prompt cache
