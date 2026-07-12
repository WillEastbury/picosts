using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sts;

/// <summary>RS256 JWT issuing + verification and a JWKS document, so any OIDC client
/// (BareMetal.Auth/Tokens) or resource server can verify tokens against the public key.</summary>
public sealed class Jwt
{
    private readonly RSA _rsa;
    public string Kid { get; }

    public Jwt(string keyPath)
    {
        _rsa = RSA.Create(2048);
        if (File.Exists(keyPath))
        {
            _rsa.ImportFromPem(File.ReadAllText(keyPath));
        }
        else
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(keyPath))!);
            File.WriteAllText(keyPath, _rsa.ExportRSAPrivateKeyPem());
        }
        // stable kid = base64url(SHA-256(DER SubjectPublicKeyInfo))
        Kid = Crypto.B64Url(SHA256.HashData(_rsa.ExportSubjectPublicKeyInfo()));
    }

    public string Sign(IDictionary<string, object> claims, TimeSpan lifetime)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, object>(claims)
        {
            ["iat"] = now,
            ["nbf"] = now,
            ["exp"] = now + (long)lifetime.TotalSeconds,
            ["jti"] = Crypto.RandomToken(12),
        };
        var header = new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = Kid };
        string h = Crypto.B64Url(JsonSerializer.SerializeToUtf8Bytes(header));
        string p = Crypto.B64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        string signingInput = $"{h}.{p}";
        byte[] sig = _rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Crypto.B64Url(sig)}";
    }

    /// <summary>Verify signature + exp/nbf. Returns the claims dict, or null if invalid.</summary>
    public Dictionary<string, JsonElement>? Verify(string token, string? expectedIssuer = null, string? expectedAudience = null)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return null;
            byte[] sig = Crypto.B64UrlDecode(parts[2]);
            if (!_rsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), sig,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                return null;
            var claims = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Crypto.B64UrlDecode(parts[1]));
            if (claims == null) return null;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (claims.TryGetValue("exp", out var exp) && exp.GetInt64() < now) return null;
            if (claims.TryGetValue("nbf", out var nbf) && nbf.GetInt64() > now + 60) return null;
            if (expectedIssuer != null && (!claims.TryGetValue("iss", out var iss) || iss.GetString() != expectedIssuer)) return null;
            if (expectedAudience != null && !AudienceOk(claims, expectedAudience)) return null;
            return claims;
        }
        catch { return null; }
    }

    private static bool AudienceOk(Dictionary<string, JsonElement> claims, string aud)
    {
        if (!claims.TryGetValue("aud", out var a)) return false;
        if (a.ValueKind == JsonValueKind.String) return a.GetString() == aud;
        if (a.ValueKind == JsonValueKind.Array)
            foreach (var x in a.EnumerateArray()) if (x.GetString() == aud) return true;
        return false;
    }

    /// <summary>JWKS document (public key only) for /.well-known/jwks.json.</summary>
    public object Jwks()
    {
        RSAParameters pub = _rsa.ExportParameters(false);
        return new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid = Kid,
                    n = Crypto.B64Url(pub.Modulus!),
                    e = Crypto.B64Url(pub.Exponent!),
                }
            }
        };
    }
}
