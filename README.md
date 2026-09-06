# forge STS — a standalone OIDC/OAuth2 Security Token Service

A small, self-contained .NET (minimal API) identity provider that works **out of the
box** with the BareMetalJsTools auth family: `BareMetal.Auth` (OIDC/OAuth2 client),
`BareMetal.Tokens` (JWT), `BareMetal.Session`, `BareMetal.RBAC`, `BareMetal.Authenticator`
(TOTP) and `BareMetal.Tenant` (multi-tenancy). Generated forge apps use it as their
shared STS (a common identity across every subsystem).

> Language note: this C# implementation is the reference. It will be ported to
> **picoSTS in C**, hosted under **PicoWeb** with its hardware-accelerated crypto.

## Run

```
cd sts
dotnet build sts.csproj -c Release
$env:ASPNETCORE_URLS='http://127.0.0.1:5100'
$env:STS_ISSUER='http://127.0.0.1:5100'
dotnet run -c Release
```

On first run it seeds a `default` tenant, a public SPA client (`spa`), `admin`/`user`
roles, and an `admin` user (password from `STS_ADMIN_PASSWORD`, or a random one printed
to the console). Signing key + data persist under `STS_DATA_DIR`.

## Configuration (environment)

| Var | Default | Meaning |
|-----|---------|---------|
| `STS_ISSUER` | `http://127.0.0.1:5100` | Public issuer/authority URL (must match how clients reach it) |
| `STS_DATA_DIR` | `<app>/sts-data` | RSA signing key (`signing.key.pem`) + `store.json` |
| `STS_AUDIENCE` | `api` | `aud` claim on access tokens; resource servers validate this |
| `STS_CLIENT_REDIRECTS` | `http://127.0.0.1:8090/callback.html,...` | Allowed SPA redirect URIs |
| `STS_CLIENT_POSTLOGOUT` | `http://127.0.0.1:8090/,...` | Allowed post-logout redirect URIs |
| `STS_CORS_ORIGINS` | `http://127.0.0.1:8090,...` | Origins allowed to call `/token` and `/userinfo` |
| `STS_ADMIN_PASSWORD` | *(random, printed)* | Seed admin password |

## Endpoints

OIDC / OAuth2:
- `GET  /.well-known/openid-configuration` — discovery
- `GET  /.well-known/jwks.json` — RS256 public key (JWKS)
- `GET  /authorize` — login page (Authorization Code + PKCE S256)
- `POST /authorize` — credential post → redirect with `code`
- `POST /token` — grants: `authorization_code` (PKCE), `refresh_token` (rotating, single-use), `password` (first-party/dev)
- `GET  /userinfo` — Bearer → user claims
- `GET  /logout` — end session (validated `post_logout_redirect_uri`)

Account (Bearer):
- `POST /account/password` — change the signed-in user's password; requires
  `currentPassword` and a new 8–128 character password containing upper-case,
  lower-case, and numeric characters
- `POST /account/totp/enroll` — returns TOTP `secret` + `otpauth_uri` (enroll in any authenticator / `BareMetal.Authenticator`)
- `POST /account/totp/verify` — `code` → enables TOTP (then required at login)

Admin (Bearer + `admin` role):
- `POST /admin/users`, `GET /admin/users`
- `POST /admin/tenants` — multi-tenancy
- `POST /admin/roles` — role → permissions (drives the `permissions` claim)

## Token claims (what the client modules read)

Access token (`aud=api`): `sub`, `preferred_username`, `email`, `tid` (tenant),
`roles`, `permissions`, `scope`. `BareMetal.RBAC` reads `roles`/`permissions`/`scope`;
`BareMetal.Tenant` reads `tid`.

## Security

- RS256 JWTs signed with a persisted RSA key; public key exposed via JWKS.
- PKCE **S256 required**; `redirect_uri` matched exactly against registered client URIs.
- Passwords: PBKDF2-SHA256 (210k iters), constant-time verify.
- Refresh tokens rotate (single-use); TOTP is RFC 6238 (HMAC-SHA1, ±1 step window).
- CORS restricted to configured SPA origins.
- `password` grant is for first-party/admin/dev use; the browser SPA flow is Authorization Code + PKCE.
