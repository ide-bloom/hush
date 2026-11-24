using System.Text;
using Hush.Core;
using Hush.Core.Keys;
using Hush.Core.Scanning;

namespace Hush.Tests.Support;

/// <summary>A temporary directory deleted on dispose.</summary>
public sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "hush-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public HushPaths HushPaths => new(System.IO.Path.Combine(Path, "hush-home"));

    public string Combine(params string[] parts) => System.IO.Path.Combine([Path, .. parts]);

    public string Write(string relativePath, string content)
    {
        var full = Combine(relativePath);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content, new UTF8Encoding(false));
        return full;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // A child process may still hold a file for a moment; the OS temp cleaner will remove it.
        }
    }
}

/// <summary>Prompt context for tests (no window).</summary>
public static class TestPrompt
{
    public static PromptContext Any { get; } = PromptContext.Headless("test");
}

/// <summary>
/// Token-shaped strings assembled at runtime from fragments and a seeded RNG, so the repository never contains a
/// literal that looks like a real credential (GitHub push protection and scanners would rightly flag it).
/// </summary>
public static class FakeTokens
{
    private const string Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private const string Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private const string UrlSafe = Alnum + "-_";
    private const string Hex = "0123456789abcdef";

    public static string Random(int length, string alphabet, int seed)
    {
        var rng = new Random(seed);
        var chars = new char[length];
        for (var i = 0; i < length; i++)
        {
            chars[i] = alphabet[rng.Next(alphabet.Length)];
        }

        return new string(chars);
    }

    public static string GitHubClassic(int seed = 1) => Crc32Token("gh" + "p_", seed);

    public static string GitHubOAuth(int seed = 2) => Crc32Token("gh" + "o_", seed);

    public static string GitHubBadChecksum(int seed = 3) => "gh" + "p_" + Random(36, Alnum, seed);

    public static string Npm(int seed = 4) => Crc32Token("np" + "m_", seed);

    public static string OpenAi(int seed = 5) => "sk-" + "proj-" + Random(48, UrlSafe, seed) + "T3Blbk" + "FJ" + Random(48, UrlSafe, seed + 100);

    public static string Anthropic(int seed = 6) => "sk-" + "ant-" + "api03-" + Random(93, UrlSafe, seed) + "AA";

    public static string Google(int seed = 7) => "AI" + "za" + Random(35, UrlSafe, seed);

    public static string HuggingFace(int seed = 8) => "h" + "f_" + Random(34, Letters, seed);

    public static string GitLab(int seed = 9) => "gl" + "pat-" + Random(20, Alnum, seed);

    public static string Slack(int seed = 10) => "xo" + "xb-" + Random(12, "0123456789", seed) + "-" + Random(13, "0123456789", seed + 1) + "-" + Random(24, Alnum, seed + 2);

    public static string StripeLive(int seed = 11) => "sk" + "_live_" + Random(32, Alnum, seed);

    public static string StripeTest(int seed = 12) => "sk" + "_test_" + Random(32, Alnum, seed);

    public static string AwsKeyId(int seed = 13) => "AK" + "IA" + Random(16, Upper, seed);

    public static string AwsSecret(int seed = 14) => Random(40, Alnum + "/+", seed);

    public static string SendGrid(int seed = 15) => "S" + "G." + Random(22, UrlSafe, seed) + "." + Random(43, UrlSafe, seed + 1);

    public static string Pypi(int seed = 16) => "py" + "pi-AgEIcHlwaS5vcmc" + Random(60, UrlSafe, seed);

    public static string Twilio(int seed = 17) => Random(32, Hex, seed);

    public static string AzureStorageKey(int seed = 18) => Random(86, Alnum + "+/", seed) + "==";

    public static string GcpKeyId(int seed = 19) => Random(40, Hex, seed);

    public static string DiscordWebhook(int seed = 20) => "https://discord.com/api/" + "webhooks/" + Random(18, "0123456789", seed) + "/" + Random(68, UrlSafe, seed + 1);

    public static string SlackWebhook(int seed = 21) => "https://hooks.slack.com/" + "services/T" + Random(8, Upper, seed) + "/B" + Random(8, Upper, seed + 1) + "/" + Random(24, Alnum, seed + 2);

    public static string Jwt(int seed = 22) =>
        Base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + Base64Url("{\"sub\":\"" + Random(10, Alnum, seed) + "\",\"iat\":1700000000}") + "." + Random(43, UrlSafe, seed + 1);

    public static string Password(int seed = 23) => Random(20, Alnum, seed);

    public static string PostgresUrl(int seed = 24) => "postgres" + "://app:" + Password(seed) + "@db.internal.example:5432/app";

    public static string MySqlUrl(int seed = 26) => "mysql" + "://root:" + Password(seed) + "@localhost:3306/shop";

    public static string MongoUrl(int seed = 27) => "mongodb" + "+srv://svc:" + Password(seed) + "@cluster0.example.net/db";

    public static string GitHubFineGrained(int seed = 28) => "github" + "_pat_" + Random(22, Alnum, seed) + "_" + Random(59, Alnum, seed + 1);

    public static string OpenAiProject(int seed = 29) => "sk-" + "proj-" + Random(60, UrlSafe, seed);

    public static string DiscordBot(int seed = 30) => "M" + Random(25, Alnum, seed) + "." + Random(6, UrlSafe, seed + 1) + "." + Random(30, Alnum, seed + 2);

    public static string TwilioKeySid(int seed = 31) => "S" + "K" + Random(32, Hex, seed);

    public static string AzureOpenAi(int seed = 32) => Random(32, Alnum, seed);

    public static string DockerAuth(int seed = 33) => Convert.ToBase64String(Encoding.UTF8.GetBytes("user:" + Password(seed)));

    public static string Bearer(int seed = 34) => Random(40, Alnum, seed);

    public static string PrivateKeyHeader() => "-----BEGIN " + "PRIVATE KEY-----";

    public static string AzureClientSecret(int seed = 25) => Random(3, Alnum, seed) + "8Q" + "~" + Random(34, Alnum + "_-", seed + 1);

    private static string Crc32Token(string prefix, int seed)
    {
        var body = Random(30, Alnum, seed);
        return prefix + body + Checksums.Crc32Base62(body);
    }

    private static string Base64Url(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Audit events for tests.</summary>
public static class AuditFactory
{
    public static Hush.Core.Audit.AuditEvent Event(string action = "test") =>
        new(action, [], "ok", null, Hush.Core.Interop.ProcessInspector.Current());
}
