using System.Security.Cryptography;
using System.Text;

namespace Sts;

/// <summary>Small, dependency-free crypto helpers built on vetted platform primitives.</summary>
public static class Crypto
{
    // ---- base64url ----
    public static string B64Url(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] B64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }

    public static string RandomToken(int bytes = 32) => B64Url(RandomNumberGenerator.GetBytes(bytes));

    // ---- password hashing (PBKDF2-SHA256) ----
    public static string HashPassword(string password, int iterations = 210_000)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2$sha256${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string stored)
    {
        try
        {
            var p = stored.Split('$');
            if (p.Length != 5 || p[0] != "pbkdf2") return false;
            int iters = int.Parse(p[2]);
            byte[] salt = Convert.FromBase64String(p[3]);
            byte[] expected = Convert.FromBase64String(p[4]);
            byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iters, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch { return false; }
    }

    // ---- PKCE (S256) ----
    public static string Sha256B64Url(string input)
    {
        byte[] h = SHA256.HashData(Encoding.ASCII.GetBytes(input));
        return B64Url(h);
    }

    public static bool VerifyPkceS256(string codeVerifier, string codeChallenge) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(Sha256B64Url(codeVerifier)),
            Encoding.ASCII.GetBytes(codeChallenge));
}
