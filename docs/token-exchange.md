# Token exchange (self-serve keys)

Busbar lets a developer self-serve their **own** budgeted API key by signing in with your
identity provider, with no admin issuing a key per person. Busbar hosts the exchange itself at
one endpoint, **`/auth/token`**. A developer signs in, gets a personal key scoped to their
own budget, and points any BYOK AI tool (Cursor, VS Code, …) at it.

## How it works

```
  developer                busbar (/auth/token)                    AI tool
  ─────────                 ────────────────────                   ───────
  hit /auth/token  ──▶  1. verify identity (browser sign-in
   · browser, OR            OR a token the caller already holds)
   · a token you hold   2. map SSO group ─▶ team (role_bindings)
                        3. mint ONE self-scoped key
                           (budget from the team's child_default)
                                    │
                                    ▼
                        { api_key, key_id, … }  ──▶  point tool at
                                                     public_url + api_key
```

Re-login returns the **same** key. **Refresh** rotates it (the old key is revoked).

## The two front doors

Same endpoint, two ways in. A developer uses whichever fits what they're holding.

### GET /auth/token: the browser

A hosted sign-in page. If you've enabled more than one method, it opens with a chooser
(one button per method) first.

<svg viewBox="0 0 760 500" role="img" aria-label="Mockup of the Busbar hosted sign-in page shown in a browser window. The address bar reads busbar.example.com/auth/token. A centered sign-in card carries the Busbar brand lockup, the heading Get your API key, and subtext saying Busbar issues a personal key scoped to your budget. Below are one sign-in button per configured identity provider: Continue with Microsoft (the emphasized primary), Continue with GitHub, and Continue with Google, each being the IdP sign-in step. A footer notes the key is issued to you and tracked against your own budget." style="width:100%;height:auto;font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif">
  <rect x="0" y="0" width="760" height="500" fill="#111a2e"/>

  <!-- browser window -->
  <rect x="48" y="36" width="664" height="432" rx="12" fill="#1a2740" stroke="#2c3a52" stroke-width="1"/>
  <line x1="48" y1="80" x2="712" y2="80" stroke="#2c3a52" stroke-width="1"/>
  <circle cx="76" cy="58" r="5" fill="#3a4a64"/>
  <circle cx="96" cy="58" r="5" fill="#3a4a64"/>
  <circle cx="116" cy="58" r="5" fill="#3a4a64"/>
  <rect x="152" y="48" width="424" height="20" rx="10" fill="#111a2e" stroke="#2c3a52" stroke-width="1"/>
  <g stroke="#94a3b8" stroke-width="1.2" fill="none">
    <rect x="162" y="56.5" width="8" height="6" rx="1"/>
    <path d="M163.5 56.5v-1.5a2.5 2.5 0 015 0v1.5"/>
  </g>
  <text x="180" y="62" fill="#94a3b8" font-size="11" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">busbar.example.com/auth/token</text>

  <!-- sign-in card -->
  <rect x="224" y="104" width="312" height="356" rx="14" fill="#111a2e" stroke="#2c3a52" stroke-width="1"/>

  <!-- brand lockup -->
  <rect x="252" y="124" width="30" height="30" rx="8" fill="#182338" stroke="#2c3a52" stroke-width="1"/>
  <g transform="translate(252 124) scale(0.234)" style="color:#a3e635">
    <g transform="translate(3 0)">
      <rect x="46" y="39" width="9" height="50" rx="4.5" fill="currentColor"/>
      <g stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <line x1="36" y1="64" x2="41" y2="64" stroke-width="5"/>
        <path d="M60 45 L79 45 Q87 45 87 55" stroke-width="5"/>
        <line x1="60" y1="64" x2="72" y2="64" stroke-width="5"/>
        <path d="M60 83 L79 83 Q87 83 87 73" stroke-width="5"/>
      </g>
      <g fill="currentColor">
        <circle cx="31" cy="64" r="4.6"/>
        <circle cx="87" cy="55" r="4.6"/>
        <circle cx="76" cy="64" r="4.6"/>
        <circle cx="87" cy="73" r="4.6"/>
      </g>
    </g>
  </g>
  <text x="290" y="145" fill="#e6edf7" font-size="16" font-weight="680">Busbar</text>

  <!-- heading + subtext -->
  <text x="252" y="190" fill="#e6edf7" font-size="18" font-weight="680">Get your API key</text>
  <text x="252" y="211" fill="#94a3b8" font-size="11">Sign in with your organization account.</text>
  <text x="252" y="226" fill="#94a3b8" font-size="11">Busbar issues a personal key scoped to</text>
  <text x="252" y="241" fill="#94a3b8" font-size="11">your budget.</text>

  <!-- provider buttons (one per configured IdP) -->
  <!-- primary: Continue with Microsoft (lime emphasis) -->
  <rect x="252" y="258" width="256" height="40" rx="10" fill="#a3e635" fill-opacity="0.06" stroke="#a3e635" stroke-opacity="0.5" stroke-width="1"/>
  <g transform="translate(262 270) scale(0.762)">
    <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
    <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
    <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
    <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
  </g>
  <text x="290" y="283" fill="#e6edf7" font-size="13" font-weight="560">Continue with Microsoft</text>
  <path d="M6 4l4 4-4 4" transform="translate(492 270)" fill="none" stroke="#94a3b8" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>

  <!-- Continue with GitHub -->
  <rect x="252" y="310" width="256" height="40" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="1"/>
  <path transform="translate(262 322)" fill="#e6edf7" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>
  <text x="290" y="335" fill="#e6edf7" font-size="13" font-weight="560">Continue with GitHub</text>
  <path d="M6 4l4 4-4 4" transform="translate(492 322)" fill="none" stroke="#94a3b8" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>

  <!-- Continue with Google -->
  <rect x="252" y="362" width="256" height="40" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="1"/>
  <g transform="translate(262 374) scale(0.889)">
    <path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 01-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z"/>
    <path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.33A9 9 0 009 18z"/>
    <path fill="#FBBC05" d="M3.97 10.72a5.4 5.4 0 010-3.44V4.95H.96a9 9 0 000 8.1l3.01-2.33z"/>
    <path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58C13.47.9 11.43 0 9 0A9 9 0 00.96 4.95l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/>
  </g>
  <text x="290" y="387" fill="#e6edf7" font-size="13" font-weight="560">Continue with Google</text>
  <path d="M6 4l4 4-4 4" transform="translate(492 374)" fill="none" stroke="#94a3b8" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>

  <!-- footer -->
  <line x1="252" y1="418" x2="508" y2="418" stroke="#2c3a52" stroke-width="1"/>
  <text x="252" y="436" fill="#94a3b8" font-size="11">Issued to you, tracked against your own budget.</text>
  <text x="252" y="452" fill="#94a3b8" font-size="10" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">busbar.example.com</text>
</svg>

### POST /auth/token: headless

Present an IdP token you already hold (a CI job, an internal tool, `az account
get-access-token`, …) and get the key back as JSON:

```bash
curl -X POST https://busbar.example.com/auth/token \
  -H "Authorization: Bearer $OIDC_TOKEN"
# → {
#     "api_key": "sk-bb-…",     # the personal key: use as your tool's API key
#     "key_id":  "vk_…",        # its stable id
#     "group":   "user:<sub>",  # the personal budget bucket it charges through
#     "exp":     1754006400     # expiry, Unix seconds (now + key_ttl)
#   }
```

Identity is taken from the **verified token**, never from the request body. A caller can
only ever mint their own key.

## Enable it

1. Install an auth method plugin: [OIDC](/plugins/auth/oidc/),
   [GitHub](/plugins/auth/github/), or [LDAP](/plugins/auth/ldap/).
2. Set **`public_url`** to the base developers' browsers actually reach.
3. Declare the provider under **`identity-providers:`** with a `browser_login:` block. (1.5.3: the
   retired parallel `auth.methods:` map folded into the provider definition. A client id/secret
   belongs to ONE IdP registration, so it belongs on that provider.)

```yaml
public_url: "https://busbar.example.com"     # busbar builds /auth/token against this
identity-providers:
  oidc:
    module: oidc
    settings:
      issuer:   "https://login.microsoftonline.com/<tenant>/v2.0"
      audience: "<client-id>"
    browser_login:                           # presence turns on the hosted sign-in button;
      client_secret: { env: OIDC_CLIENT_SECRET }   # omit the block for headless-only
auth:
  key_ttl: 90d                               # issued-key lifetime (admin-set; default 90d)
  chain: [keys, oidc]                        # reference the provider BY BARE NAME
  role_bindings:
    oidc:                                    # NESTED BY PROVIDER NAME
      "<sso-group>": { group: engineering }  # which team's child_default budgets each dev
```

That's the shape. The **full per-provider config** (issuer, audience, claim mapping, IdP
walkthroughs) lives on the plugin page: [OIDC](/plugins/auth/oidc/) ·
[GitHub](/plugins/auth/github/) · [LDAP](/plugins/auth/ldap/).

> With Entra ID, `"<sso-group>"` above is **not** necessarily your security group's display
> name. What it must be depends on `role_claim` (app role Value string vs. security group
> Object ID GUID), and the redirect URI, client secret, and role/group setup have their own
> gotchas too. This trips people up constantly; see
> [Walkthrough: configuring OIDC with Microsoft Entra ID](configuration.md#auth-plugins) for the
> full click-by-click reference before you bind a role.

## Key facts

- **One key per person.** Deterministic from the verified identity, so it re-shows on every
  login; a **Refresh** button rotates it (old key revoked).
- **`auth.key_ttl`.** Admin-set key lifetime, default **90d**; a re-login re-issues within
  the window.
- **Self-scoped.** Identity comes from the verified token, never the request body. The
  exchange can only mint the caller's own `user:<sub>` key.
- **Budget auto-provisioned.** The `user:<sub>` bucket is created on **first exchange**,
  limits stamped from the mapped team's `child_default`.
- **Any auth method.** Works identically with `oidc`, `github`, or `ldap`.
- **Don't want issued keys?** Put the method in `auth.chain` instead (e.g.
  `chain: [oidc]`) to verify a live IdP token on **every** request and issue no key. The
  two compose. See [Configuration](configuration.md#auth).
