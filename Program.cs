using System.Text;
using System.Text.Json;
using Sts;

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.PropertyNamingPolicy = null);

// ---- config (env) ----
string Env(string k, string d) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : d;
string issuer   = Env("STS_ISSUER", "http://127.0.0.1:5100").TrimEnd('/');
string dataDir  = Env("STS_DATA_DIR", Path.Combine(AppContext.BaseDirectory, "sts-data"));
string audience = Env("STS_AUDIENCE", "api");
var redirects   = Env("STS_CLIENT_REDIRECTS", "http://127.0.0.1:8090/callback.html,http://localhost:8090/callback.html")
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
var postLogouts = Env("STS_CLIENT_POSTLOGOUT", "http://127.0.0.1:8090/,http://localhost:8090/")
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
var corsOrigins = Env("STS_CORS_ORIGINS", "http://127.0.0.1:8090,http://localhost:8090")
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

Directory.CreateDirectory(dataDir);
var jwt = new Jwt(Path.Combine(dataDir, "signing.key.pem"));
var store = Store.Load(Path.Combine(dataDir, "store.json"));
string adminPw = Env("STS_ADMIN_PASSWORD", "");
bool generatedAdminPw = adminPw.Length == 0;
if (generatedAdminPw) adminPw = Crypto.RandomToken(9);
store.SeedDefaults(redirects, postLogouts, adminPw);

builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.WithOrigins(corsOrigins).AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

var app = builder.Build();
app.UseCors();
app.UseStaticFiles();

TimeSpan accessLife = TimeSpan.FromMinutes(15);
TimeSpan refreshLife = TimeSpan.FromDays(14);
TimeSpan idLife = TimeSpan.FromMinutes(15);

// ---- helpers ----
Dictionary<string, object> BaseClaims(User u, string scope)
{
    var roles = store.EffectiveRoles(u);
    var perms = store.PermissionsFor(roles);
    return new Dictionary<string, object>
    {
        ["iss"] = issuer,
        ["sub"] = u.Id,
        ["preferred_username"] = u.Username,
        ["email"] = u.Email,
        ["tid"] = u.TenantId,
        ["roles"] = roles,
        ["groups"] = u.Groups,
        ["permissions"] = perms,
        ["scope"] = scope,
    };
}

string IssueAccess(User u, string scope, string clientId)
{
    var c = BaseClaims(u, scope);
    c["aud"] = audience;
    c["azp"] = clientId;
    c["typ"] = "at+jwt";
    return jwt.Sign(c, accessLife);
}

string IssueId(User u, string clientId, string? nonce)
{
    var c = BaseClaims(u, "openid");
    c["aud"] = clientId;
    c["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    if (nonce != null) c["nonce"] = nonce;
    return jwt.Sign(c, idLife);
}

object TokenResponse(User u, string scope, string clientId, string? nonce, bool withId, bool withRefresh)
{
    var resp = new Dictionary<string, object>
    {
        ["access_token"] = IssueAccess(u, scope, clientId),
        ["token_type"] = "Bearer",
        ["expires_in"] = (int)accessLife.TotalSeconds,
        ["scope"] = scope,
    };
    if (withId) resp["id_token"] = IssueId(u, clientId, nonce);
    if (withRefresh)
    {
        var rt = new RefreshToken(Crypto.RandomToken(32), u.Id, clientId, scope, DateTimeOffset.UtcNow.Add(refreshLife));
        store.PutRefresh(rt);
        resp["refresh_token"] = rt.Token;
    }
    return resp;
}

User? BearerUser(HttpContext ctx)
{
    string? auth = ctx.Request.Headers.Authorization;
    if (auth == null || !auth.StartsWith("Bearer ")) return null;
    var claims = jwt.Verify(auth[7..], issuer, audience);
    if (claims == null || !claims.TryGetValue("sub", out var sub)) return null;
    return store.UserById(sub.GetString() ?? "");
}

bool IsAdmin(User u) => u.Roles.Contains("admin");

// ================= OIDC discovery =================
app.MapGet("/.well-known/openid-configuration", () => Results.Json(new Dictionary<string, object>
{
    ["issuer"] = issuer,
    ["authorization_endpoint"] = $"{issuer}/authorize",
    ["token_endpoint"] = $"{issuer}/token",
    ["userinfo_endpoint"] = $"{issuer}/userinfo",
    ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
    ["end_session_endpoint"] = $"{issuer}/logout",
    ["response_types_supported"] = new[] { "code" },
    ["grant_types_supported"] = new[] { "authorization_code", "refresh_token", "password" },
    ["code_challenge_methods_supported"] = new[] { "S256" },
    ["scopes_supported"] = new[] { "openid", "profile", "email", "offline_access" },
    ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
    ["token_endpoint_auth_methods_supported"] = new[] { "none", "client_secret_post" },
    ["subject_types_supported"] = new[] { "public" },
    ["claims_supported"] = new[] { "sub", "preferred_username", "email", "tid", "roles", "permissions" },
}));

app.MapGet("/.well-known/jwks.json", () => Results.Json(jwt.Jwks()));

// ================= authorize (login) =================
string LoginPage(IDictionary<string, string?> q, string? error) => $@"<!doctype html><html><head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Sign in</title><style>body{{font-family:system-ui,Segoe UI,Arial;background:#0d1c28;color:#e6edf3;display:flex;min-height:100vh;align-items:center;justify-content:center}}
form{{background:#142635;padding:28px;border-radius:10px;width:320px;box-shadow:0 10px 30px rgba(0,0,0,.4)}}
h1{{font-size:18px;margin:0 0 16px}}label{{display:block;margin:10px 0 4px;font-size:13px;color:#9fb0c0}}
input{{width:100%;box-sizing:border-box;padding:9px;border:1px solid #294a63;border-radius:6px;background:#0d1c28;color:#e6edf3}}
button{{margin-top:16px;width:100%;padding:10px;border:0;border-radius:6px;background:#2f81f7;color:#fff;font-weight:600;cursor:pointer}}
.err{{color:#ff7b72;font-size:13px;margin-top:10px}}</style></head><body>
<form method='post' action='/authorize'>
<h1>Sign in</h1>
<label>Username or email</label><input name='username' autofocus required>
<label>Password</label><input name='password' type='password' required>
<label>Authenticator code (if enabled)</label><input name='totp' autocomplete='one-time-code' inputmode='numeric'>
<input type='hidden' name='client_id' value='{q["client_id"]}'>
<input type='hidden' name='redirect_uri' value='{q["redirect_uri"]}'>
<input type='hidden' name='response_type' value='{q["response_type"]}'>
<input type='hidden' name='scope' value='{q["scope"]}'>
<input type='hidden' name='state' value='{q["state"]}'>
<input type='hidden' name='nonce' value='{q["nonce"]}'>
<input type='hidden' name='code_challenge' value='{q["code_challenge"]}'>
<input type='hidden' name='code_challenge_method' value='{q["code_challenge_method"]}'>
<input type='hidden' name='tenant' value='{q["tenant"]}'>
<button>Sign in</button>
{(error != null ? $"<div class='err'>{error}</div>" : "")}
</form></body></html>";

string? Q(HttpRequest r, string k) => r.Query[k].Count > 0 ? r.Query[k].ToString() : null;

app.MapGet("/authorize", (HttpRequest r) =>
{
    string? clientId = Q(r, "client_id");
    string? redirect = Q(r, "redirect_uri");
    if (clientId == null || !store.Clients.TryGetValue(clientId, out var client))
        return Results.BadRequest("unknown client_id");
    if (redirect == null || !client.RedirectUris.Contains(redirect))
        return Results.BadRequest("invalid redirect_uri");
    if ((Q(r, "response_type") ?? "code") != "code")
        return Results.BadRequest("unsupported response_type");
    if ((Q(r, "code_challenge_method") ?? "S256") != "S256")
        return Results.BadRequest("code_challenge_method must be S256");
    var q = new Dictionary<string, string?>
    {
        ["client_id"] = clientId, ["redirect_uri"] = redirect,
        ["response_type"] = "code", ["scope"] = Q(r, "scope") ?? "openid profile",
        ["state"] = Q(r, "state"), ["nonce"] = Q(r, "nonce"),
        ["code_challenge"] = Q(r, "code_challenge"), ["code_challenge_method"] = "S256",
        ["tenant"] = Q(r, "tenant") ?? "default",
    };
    return Results.Content(LoginPage(q, null), "text/html");
});

app.MapPost("/authorize", async (HttpRequest r) =>
{
    var f = await r.ReadFormAsync();
    string F(string k) => f[k].ToString();
    if (!store.Clients.TryGetValue(F("client_id"), out var client) || !client.RedirectUris.Contains(F("redirect_uri")))
        return Results.BadRequest("invalid client/redirect");

    var user = store.FindUser(F("username"), string.IsNullOrEmpty(F("tenant")) ? "default" : F("tenant"));
    var q = f.Keys.ToDictionary(k => k, k => (string?)f[k].ToString());
    if (user == null || !Crypto.VerifyPassword(F("password"), user.PasswordHash))
        return Results.Content(LoginPage(q, "Invalid credentials"), "text/html");
    if (user.TotpEnabled && !Totp.Verify(user.TotpSecret!, F("totp")))
        return Results.Content(LoginPage(q, "Invalid or missing authenticator code"), "text/html");

    var code = new AuthCode(Crypto.RandomToken(24), F("client_id"), F("redirect_uri"),
        F("code_challenge"), user.Id, F("scope"), string.IsNullOrEmpty(F("nonce")) ? null : F("nonce"),
        DateTimeOffset.UtcNow.AddMinutes(2));
    store.PutCode(code);
    var sep = F("redirect_uri").Contains('?') ? "&" : "?";
    var loc = $"{F("redirect_uri")}{sep}code={Uri.EscapeDataString(code.Code)}";
    if (!string.IsNullOrEmpty(F("state"))) loc += $"&state={Uri.EscapeDataString(F("state"))}";
    return Results.Redirect(loc);
});

// ================= token =================
app.MapPost("/token", async (HttpRequest r) =>
{
    var f = await r.ReadFormAsync();
    string F(string k) => f[k].ToString();
    string grant = F("grant_type");

    if (grant == "authorization_code")
    {
        var code = store.TakeCode(F("code"));
        if (code == null) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
        if (code.ClientId != F("client_id") || code.RedirectUri != F("redirect_uri"))
            return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
        if (!Crypto.VerifyPkceS256(F("code_verifier"), code.CodeChallenge))
            return Results.Json(new { error = "invalid_grant", error_description = "PKCE failed" }, statusCode: 400);
        var u = store.UserById(code.UserId);
        if (u == null) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
        bool offline = code.Scope.Split(' ').Contains("offline_access");
        bool openid = code.Scope.Split(' ').Contains("openid");
        return Results.Json(TokenResponse(u, code.Scope, code.ClientId, code.Nonce, openid, offline));
    }

    if (grant == "refresh_token")
    {
        var rt = store.TakeRefresh(F("refresh_token"));   // rotation: single-use
        if (rt == null) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
        var u = store.UserById(rt.UserId);
        if (u == null || u.Disabled) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
        return Results.Json(TokenResponse(u, rt.Scope, rt.ClientId, null,
            rt.Scope.Split(' ').Contains("openid"), true));
    }

    if (grant == "password")   // resource-owner (first-party/dev + admin CLI)
    {
        if (!store.Clients.TryGetValue(F("client_id"), out var client))
            return Results.Json(new { error = "invalid_client" }, statusCode: 400);
        var u = store.FindUser(F("username"), string.IsNullOrEmpty(F("tenant")) ? "default" : F("tenant"));
        if (u == null || !Crypto.VerifyPassword(F("password"), u.PasswordHash))
            return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
        if (u.TotpEnabled && !Totp.Verify(u.TotpSecret!, F("totp")))
            return Results.Json(new { error = "invalid_grant", error_description = "totp required" }, statusCode: 400);
        string scope = string.IsNullOrEmpty(F("scope")) ? "openid profile offline_access" : F("scope");
        return Results.Json(TokenResponse(u, scope, F("client_id"), null,
            scope.Split(' ').Contains("openid"), scope.Split(' ').Contains("offline_access")));
    }

    return Results.Json(new { error = "unsupported_grant_type" }, statusCode: 400);
});

// ================= userinfo =================
app.MapGet("/userinfo", (HttpContext ctx) =>
{
    var u = BearerUser(ctx);
    if (u == null) return Results.Unauthorized();
    var roles = store.EffectiveRoles(u);
    return Results.Json(new Dictionary<string, object>
    {
        ["sub"] = u.Id, ["preferred_username"] = u.Username, ["email"] = u.Email,
        ["tid"] = u.TenantId, ["roles"] = roles, ["groups"] = u.Groups,
        ["permissions"] = store.PermissionsFor(roles),
    });
});

// ================= logout (end session) =================
app.MapGet("/logout", (HttpRequest r) =>
{
    string? post = Q(r, "post_logout_redirect_uri");
    // stateless bearer: nothing server-side to clear beyond refresh tokens (client drops tokens)
    if (post != null && store.Clients.Values.Any(c => c.PostLogoutRedirectUris.Contains(post!)))
        return Results.Redirect(post);
    return Results.Content("<!doctype html><p>Signed out.</p>", "text/html");
});

// ================= account self-service (TOTP) =================
app.MapPost("/account/totp/enroll", (HttpContext ctx) =>
{
    var u = BearerUser(ctx);
    if (u == null) return Results.Unauthorized();
    string secret = Totp.NewSecret();
    u.TotpSecret = secret; u.TotpEnabled = false;   // pending until verified
    store.Save();
    return Results.Json(new
    {
        secret,
        otpauth_uri = Totp.OtpAuthUri(secret, u.Username, "forge-sts"),
    });
});

app.MapPost("/account/totp/verify", async (HttpContext ctx) =>
{
    var u = BearerUser(ctx);
    if (u == null) return Results.Unauthorized();
    var f = await ctx.Request.ReadFormAsync();
    if (u.TotpSecret == null || !Totp.Verify(u.TotpSecret, f["code"].ToString()))
        return Results.Json(new { error = "invalid_code" }, statusCode: 400);
    u.TotpEnabled = true; store.Save();
    return Results.Json(new { enabled = true });
});

// ================= admin (RBAC-guarded) =================
IResult? RequireAdmin(HttpContext ctx, out User? admin)
{
    admin = BearerUser(ctx);
    if (admin == null) return Results.Unauthorized();
    if (!IsAdmin(admin)) return Results.Json(new { error = "forbidden" }, statusCode: 403);
    return null;
}

app.MapPost("/admin/users", async (HttpContext ctx) =>
{
    var guard = RequireAdmin(ctx, out _);
    if (guard is not null) return guard;
    var dto = await ctx.Request.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
    if (dto == null || !dto.ContainsKey("username") || !dto.ContainsKey("password"))
        return Results.BadRequest("username + password required");
    var u = new User
    {
        Username = dto["username"].GetString()!,
        Email = dto.TryGetValue("email", out var e) ? e.GetString() ?? "" : "",
        TenantId = dto.TryGetValue("tenant", out var t) ? t.GetString() ?? "default" : "default",
        PasswordHash = Crypto.HashPassword(dto["password"].GetString()!),
        Roles = dto.TryGetValue("roles", out var rs) && rs.ValueKind == JsonValueKind.Array
            ? rs.EnumerateArray().Select(x => x.GetString()!).ToList() : new() { "user" },
        Groups = dto.TryGetValue("groups", out var gs) && gs.ValueKind == JsonValueKind.Array
            ? gs.EnumerateArray().Select(x => x.GetString()!).ToList() : new(),
    };
    store.AddUser(u);
    return Results.Json(new { u.Id, u.Username, u.TenantId, u.Roles, u.Groups });
});

app.MapGet("/admin/users", (HttpContext ctx) =>
{
    var guard = RequireAdmin(ctx, out _);
    if (guard is not null) return guard;
    return Results.Json(store.Users.Values.Select(u => new { u.Id, u.Username, u.Email, u.TenantId, u.Roles, u.Groups, u.TotpEnabled }));
});

app.MapPut("/admin/users/{id}/groups", async (string id, HttpContext ctx) =>
{
    var guard = RequireAdmin(ctx, out _);
    if (guard is not null) return guard;
    var u = store.UserById(id);
    if (u == null) return Results.NotFound();
    var dto = await ctx.Request.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
    if (dto != null && dto.TryGetValue("groups", out var gs) && gs.ValueKind == JsonValueKind.Array)
        u.Groups = gs.EnumerateArray().Select(x => x.GetString()!).ToList();
    store.Save();
    return Results.Json(new { u.Id, u.Groups, effectiveRoles = store.EffectiveRoles(u) });
});

app.MapPost("/admin/groups", async (HttpContext ctx) =>
{
    var guard = RequireAdmin(ctx, out _);
    if (guard is not null) return guard;
    var dto = await ctx.Request.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
    if (dto == null || !dto.ContainsKey("id")) return Results.BadRequest("id required");
    string id = dto["id"].GetString()!;
    store.Groups[id] = new Group
    {
        Id = id,
        Name = dto.TryGetValue("name", out var n) ? n.GetString() ?? id : id,
        ParentId = dto.TryGetValue("parent", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null,
        Roles = dto.TryGetValue("roles", out var rs) && rs.ValueKind == JsonValueKind.Array
            ? rs.EnumerateArray().Select(x => x.GetString()!).ToList() : new(),
    };
    store.Save();
    return Results.Json(store.Groups[id]);
});

app.MapGet("/admin/groups", (HttpContext ctx) =>
{
    var guard = RequireAdmin(ctx, out _);
    if (guard is not null) return guard;
    return Results.Json(store.Groups.Values);
});

// Provision the whole auth model from an ontology auth seed (roles + nested groups + principals).
app.MapPost("/admin/import", async (HttpContext ctx) =>
{
    var guard = RequireAdmin(ctx, out _);
    if (guard is not null) return guard;
    var dto = await ctx.Request.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
    if (dto == null) return Results.BadRequest("body required");
    int nr = 0, ng = 0, np = 0;
    if (dto.TryGetValue("roles", out var roles) && roles.ValueKind == JsonValueKind.Array)
        foreach (var r in roles.EnumerateArray())
        {
            string name = r.GetProperty("name").GetString()!;
            store.RolePermissions[name] = r.TryGetProperty("permissions", out var ps) && ps.ValueKind == JsonValueKind.Array
                ? ps.EnumerateArray().Select(x => x.GetString()!).ToList() : new();
            nr++;
        }
    if (dto.TryGetValue("groups", out var groups) && groups.ValueKind == JsonValueKind.Array)
        foreach (var g in groups.EnumerateArray())
        {
            string id = g.GetProperty("id").GetString()!;
            store.Groups[id] = new Group
            {
                Id = id,
                Name = g.TryGetProperty("name", out var n) ? n.GetString() ?? id : id,
                ParentId = g.TryGetProperty("parent", out var pp) && pp.ValueKind == JsonValueKind.String ? pp.GetString() : null,
                Roles = g.TryGetProperty("roles", out var grs) && grs.ValueKind == JsonValueKind.Array
                    ? grs.EnumerateArray().Select(x => x.GetString()!).ToList() : new(),
            };
            ng++;
        }
    if (dto.TryGetValue("principals", out var principals) && principals.ValueKind == JsonValueKind.Array)
        foreach (var pr in principals.EnumerateArray())
        {
            string username = pr.GetProperty("username").GetString()!;
            string tenant = pr.TryGetProperty("tenant", out var tt) ? tt.GetString() ?? "default" : "default";
            var existing = store.FindUser(username, tenant);
            var user = existing ?? new User { Username = username, TenantId = tenant,
                PasswordHash = Crypto.HashPassword(pr.TryGetProperty("password", out var pw) ? pw.GetString()! : Crypto.RandomToken(9)) };
            user.Email = pr.TryGetProperty("email", out var em) ? em.GetString() ?? user.Email : user.Email;
            if (pr.TryGetProperty("roles", out var prr) && prr.ValueKind == JsonValueKind.Array)
                user.Roles = prr.EnumerateArray().Select(x => x.GetString()!).ToList();
            if (pr.TryGetProperty("groups", out var prg) && prg.ValueKind == JsonValueKind.Array)
                user.Groups = prg.EnumerateArray().Select(x => x.GetString()!).ToList();
            store.Users[user.Id] = user;
            np++;
        }
    store.Save();
    return Results.Json(new { roles = nr, groups = ng, principals = np });
});

app.MapPost("/admin/tenants", async (HttpContext ctx) =>
{
    var guard = RequireAdmin(ctx, out _);
    if (guard is not null) return guard;
    var dto = await ctx.Request.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
    if (dto == null || !dto.ContainsKey("id")) return Results.BadRequest("id required");
    string id = dto["id"].GetString()!;
    store.Tenants[id] = new Tenant { Id = id, Name = dto.TryGetValue("name", out var n) ? n.GetString() ?? id : id };
    store.Save();
    return Results.Json(store.Tenants[id]);
});

app.MapPost("/admin/roles", async (HttpContext ctx) =>
{
    var guard = RequireAdmin(ctx, out _);
    if (guard is not null) return guard;
    var dto = await ctx.Request.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
    if (dto == null || !dto.ContainsKey("role")) return Results.BadRequest("role required");
    string role = dto["role"].GetString()!;
    store.RolePermissions[role] = dto.TryGetValue("permissions", out var ps) && ps.ValueKind == JsonValueKind.Array
        ? ps.EnumerateArray().Select(x => x.GetString()!).ToList() : new();
    store.Save();
    return Results.Json(new { role, permissions = store.RolePermissions[role] });
});

app.MapGet("/health", () => Results.Json(new { status = "ok", issuer, kid = jwt.Kid }));

Console.WriteLine($"[sts] issuer   = {issuer}");
Console.WriteLine($"[sts] data dir = {dataDir}");
Console.WriteLine($"[sts] cors     = {string.Join(", ", corsOrigins)}");
Console.WriteLine($"[sts] spa redirect_uris = {string.Join(", ", redirects)}");
if (generatedAdminPw)
    Console.WriteLine($"[sts] SEEDED admin password (set STS_ADMIN_PASSWORD to override): {adminPw}");

app.Run();
