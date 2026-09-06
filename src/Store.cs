using System.Collections.Concurrent;
using System.Text.Json;

namespace Sts;

public sealed class User
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n");
    public string Username { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string TenantId { get; set; } = "default";
    public List<string> Roles { get; set; } = new();     // roles assigned directly to this principal
    public List<string> Groups { get; set; } = new();     // group ids this principal belongs to
    public string? TotpSecret { get; set; }
    public bool TotpEnabled { get; set; }
    public bool Disabled { get; set; }
}

public sealed class SeedUser
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Email { get; set; } = "";
    public string TenantId { get; set; } = "default";
    public List<string> Roles { get; set; } = new();
}

/// <summary>A group of principals. Nestable via ParentId; roles may be assigned to a group,
/// and are inherited by members of the group and of its descendant groups.</summary>
public sealed class Group
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string? ParentId { get; set; }
    public List<string> Roles { get; set; } = new();
}

public sealed class Client
{
    public string ClientId { get; set; } = "";
    public bool Public { get; set; } = true;            // SPA/public client -> PKCE, no secret
    public string? Secret { get; set; }                  // confidential clients only
    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutRedirectUris { get; set; } = new();
    public List<string> AllowedScopes { get; set; } = new() { "openid", "profile", "email", "offline_access" };
}

public sealed class Tenant
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
}

public sealed record AuthCode(string Code, string ClientId, string RedirectUri, string CodeChallenge,
    string UserId, string Scope, string? Nonce, DateTimeOffset Expiry);

public sealed record RefreshToken(string Token, string UserId, string ClientId, string Scope, DateTimeOffset Expiry);

/// <summary>Durable STS data (users/clients/tenants/roles) persisted to JSON; short-lived
/// auth codes + refresh tokens kept in memory. Thread-safe.</summary>
public sealed class Store
{
    private readonly string _path;
    private readonly object _lock = new();

    public Dictionary<string, User> Users { get; set; } = new();          // by Id
    public Dictionary<string, Client> Clients { get; set; } = new();      // by ClientId
    public Dictionary<string, Tenant> Tenants { get; set; } = new();      // by Id
    public Dictionary<string, Group> Groups { get; set; } = new();        // by Id
    public Dictionary<string, List<string>> RolePermissions { get; set; } = new();

    // transient (memory only)
    private readonly ConcurrentDictionary<string, AuthCode> _codes = new();
    private readonly ConcurrentDictionary<string, RefreshToken> _refresh = new();

    private Store(string path) { _path = path; }

    public static Store Load(string path)
    {
        var s = new Store(path);
        if (File.Exists(path))
        {
            var data = JsonSerializer.Deserialize<Persisted>(File.ReadAllText(path));
            if (data != null)
            {
                s.Users = data.Users; s.Clients = data.Clients;
                s.Tenants = data.Tenants; s.RolePermissions = data.RolePermissions;
                s.Groups = data.Groups;
            }
        }
        return s;
    }

    private sealed class Persisted
    {
        public Dictionary<string, User> Users { get; set; } = new();
        public Dictionary<string, Client> Clients { get; set; } = new();
        public Dictionary<string, Tenant> Tenants { get; set; } = new();
        public Dictionary<string, Group> Groups { get; set; } = new();
        public Dictionary<string, List<string>> RolePermissions { get; set; } = new();
    }

    public void Save()
    {
        lock (_lock)
        {
            var data = new Persisted { Users = Users, Clients = Clients, Tenants = Tenants,
                RolePermissions = RolePermissions, Groups = Groups };
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            File.WriteAllText(_path, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    // ---- users ----
    public User? FindUser(string usernameOrEmail, string tenantId) => Users.Values.FirstOrDefault(u =>
        u.TenantId == tenantId && !u.Disabled &&
        (string.Equals(u.Username, usernameOrEmail, StringComparison.OrdinalIgnoreCase) ||
         string.Equals(u.Email, usernameOrEmail, StringComparison.OrdinalIgnoreCase)));

    public User? UserById(string id) => Users.TryGetValue(id, out var u) ? u : null;

    public User AddUser(User u) { lock (_lock) { Users[u.Id] = u; } Save(); return u; }

    // ---- effective roles: direct principal roles UNION roles from every group the
    //      principal belongs to, plus those groups' ancestors (nested inheritance) ----
    public List<string> EffectiveRoles(User u)
    {
        var roles = new HashSet<string>(u.Roles);
        var seen = new HashSet<string>();
        var queue = new Queue<string>(u.Groups);
        while (queue.Count > 0)
        {
            string gid = queue.Dequeue();
            if (!seen.Add(gid) || !Groups.TryGetValue(gid, out var g)) continue;
            foreach (var r in g.Roles) roles.Add(r);
            if (g.ParentId != null) queue.Enqueue(g.ParentId);   // inherit ancestor roles
        }
        return roles.ToList();
    }

    // ---- permissions from roles ----
    public List<string> PermissionsFor(IEnumerable<string> roles)
    {
        var perms = new HashSet<string>();
        foreach (var r in roles)
            if (RolePermissions.TryGetValue(r, out var ps))
                foreach (var p in ps) perms.Add(p);
        return perms.ToList();
    }

    public List<string> EffectivePermissions(User u) => PermissionsFor(EffectiveRoles(u));

    // ---- auth codes (single-use, short lived) ----
    public void PutCode(AuthCode c) => _codes[c.Code] = c;
    public AuthCode? TakeCode(string code) =>
        _codes.TryRemove(code, out var c) && c.Expiry > DateTimeOffset.UtcNow ? c : null;

    // ---- refresh tokens (rotating) ----
    public void PutRefresh(RefreshToken t) => _refresh[t.Token] = t;
    public RefreshToken? TakeRefresh(string token) =>
        _refresh.TryRemove(token, out var t) && t.Expiry > DateTimeOffset.UtcNow ? t : null;
    public void RevokeUserRefresh(string userId)
    {
        foreach (var kv in _refresh.Where(x => x.Value.UserId == userId).ToList())
            _refresh.TryRemove(kv.Key, out _);
    }

    /// <summary>Seed a default tenant, public SPA client, roles and an admin user on first run.</summary>
    public void SeedDefaults(IEnumerable<string> redirectUris, IEnumerable<string> postLogoutUris, string adminPassword)
    {
        bool changed = false;
        if (Tenants.Count == 0) { Tenants["default"] = new Tenant { Id = "default", Name = "Default" }; changed = true; }
        if (RolePermissions.Count == 0)
        {
            RolePermissions["admin"] = new() { "*" };
            RolePermissions["user"] = new() { "read" };
            changed = true;
        }
        if (!Clients.ContainsKey("spa"))
        {
            Clients["spa"] = new Client
            {
                ClientId = "spa", Public = true,
                RedirectUris = redirectUris.ToList(),
                PostLogoutRedirectUris = postLogoutUris.ToList(),
            };
            changed = true;
        }
        if (!Users.Values.Any(u => u.Username == "admin"))
        {
            var admin = new User
            {
                Username = "admin", Email = "admin@localhost", TenantId = "default",
                PasswordHash = Crypto.HashPassword(adminPassword), Roles = new() { "admin" },
            };
            Users[admin.Id] = admin;   // key by Id (sub) so UserById works
            changed = true;
        }
        if (changed) Save();
    }

    public void SeedUsers(IEnumerable<SeedUser> seeds)
    {
        bool changed = false;
        foreach (var seed in seeds)
        {
            if (string.IsNullOrWhiteSpace(seed.Username) || string.IsNullOrEmpty(seed.Password))
                continue;
            if (Users.Values.Any(u =>
                u.TenantId == seed.TenantId &&
                string.Equals(u.Username, seed.Username, StringComparison.OrdinalIgnoreCase)))
                continue;

            var user = new User
            {
                Username = seed.Username.Trim(),
                Email = seed.Email.Trim(),
                TenantId = string.IsNullOrWhiteSpace(seed.TenantId) ? "default" : seed.TenantId.Trim(),
                PasswordHash = Crypto.HashPassword(seed.Password),
                Roles = seed.Roles.Count > 0 ? seed.Roles.Distinct().ToList() : new() { "user" },
            };
            Users[user.Id] = user;
            changed = true;
        }
        if (changed) Save();
    }
}
