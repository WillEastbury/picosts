using System.Security.Cryptography;
using System.Text;

namespace Sts;

/// <summary>RFC 6238 TOTP + RFC 4648 base32, for BareMetal.Authenticator compatibility.</summary>
public static class Totp
{
    private const string B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string NewSecret(int bytes = 20) => Base32Encode(RandomNumberGenerator.GetBytes(bytes));

    public static string Base32Encode(byte[] data)
    {
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(B32[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.Append(B32[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] Base32Decode(string s)
    {
        s = s.TrimEnd('=').ToUpperInvariant().Replace(" ", "");
        int buffer = 0, bits = 0;
        var outp = new List<byte>();
        foreach (char c in s)
        {
            int v = B32.IndexOf(c);
            if (v < 0) continue;
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                outp.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }
        return outp.ToArray();
    }

    /// <summary>otpauth:// URI that BareMetal.Authenticator / any authenticator app can enroll.</summary>
    public static string OtpAuthUri(string secretBase32, string account, string issuer) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}" +
        $"?secret={secretBase32}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";

    public static string Compute(string secretBase32, long counter, int digits = 6)
    {
        byte[] key = Base32Decode(secretBase32);
        byte[] msg = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(msg);
        byte[] hash = new HMACSHA1(key).ComputeHash(msg);
        int offset = hash[^1] & 0x0F;
        int bin = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) |
                  (hash[offset + 2] << 8) | hash[offset + 3];
        int otp = bin % (int)Math.Pow(10, digits);
        return otp.ToString().PadLeft(digits, '0');
    }

    /// <summary>Verify a code against the current 30s window +/- 1 step (clock skew tolerant).</summary>
    public static bool Verify(string secretBase32, string code, int window = 1)
    {
        if (string.IsNullOrWhiteSpace(code)) return false;
        long step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        for (long w = -window; w <= window; w++)
        {
            string expected = Compute(secretBase32, step + w);
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(code)))
                return true;
        }
        return false;
    }
}
