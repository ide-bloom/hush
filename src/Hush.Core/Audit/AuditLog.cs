using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hush.Core.Interop;

namespace Hush.Core.Audit;

/// <summary>Something worth recording. Holds secret names, never values.</summary>
/// <param name="Action">Dotted action name, for example <c>secret.read</c>.</param>
/// <param name="Secrets">Qualified secret names involved.</param>
/// <param name="Result"><c>ok</c>, <c>denied</c>, <c>error</c>, and so on.</param>
/// <param name="Detail">Optional context (for example the program launched by <c>hush run</c>).</param>
/// <param name="Process">The requesting process.</param>
public sealed record AuditEvent(string Action, IReadOnlyList<string> Secrets, string Result, string? Detail, ProcessIdentity? Process);

/// <summary>One parsed line of the audit log.</summary>
public sealed record AuditRecord(
    ulong Sequence,
    DateTimeOffset Timestamp,
    string Action,
    IReadOnlyList<string> Secrets,
    string Result,
    string? Detail,
    int? Pid,
    string? Process,
    int? ParentPid,
    string? ParentProcess,
    bool Deferred,
    string Previous,
    string Mac);

/// <summary>Outcome of <see cref="AuditLog.Verify"/>.</summary>
/// <param name="IsValid">True when the chain is intact and matches the head stored in the vault.</param>
/// <param name="EntryCount">Number of entries read.</param>
/// <param name="Problems">Human-readable descriptions of every inconsistency found.</param>
/// <param name="Warnings">Non-fatal observations, such as an entry written just before a crash.</param>
public sealed record AuditVerification(bool IsValid, int EntryCount, IReadOnlyList<string> Problems, IReadOnlyList<string> Warnings);

/// <summary>
/// The append-only audit log. Each line is a JSON object whose <c>mac</c> is
/// HMAC-SHA256(audit key, line-without-mac); each entry's <c>prev</c> is the previous entry's MAC, so
/// editing or deleting any entry breaks the chain. The vault header stores the last sequence number and
/// MAC, which is how truncation of the tail is detected.
/// </summary>
public sealed class AuditLog
{
    private const string MacMarker = ",\"mac\":\"";

    /// <summary>Opens the log at <paramref name="path"/>.</summary>
    public AuditLog(string path) => Path = path;

    /// <summary>The log file.</summary>
    public string Path { get; }

    /// <summary>The MAC that precedes the first entry.</summary>
    public static byte[] GenesisMac => new byte[32];

    /// <summary>
    /// Appends an entry and returns its sequence number and MAC. Callers hold the vault lock and store the
    /// returned head in the vault header.
    /// </summary>
    public (ulong Sequence, byte[] Mac) Append(AuditEvent auditEvent, ReadOnlySpan<byte> key, ulong previousSequence, ReadOnlySpan<byte> previousMac, DateTimeOffset timestamp, bool deferred = false)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        var sequence = previousSequence + 1;
        var body = BuildBody(auditEvent, sequence, timestamp, deferred, previousMac);
        var mac = HMACSHA256.HashData(key, body);
        var line = new byte[body.Length - 1 + MacMarker.Length + 44 + 3];
        var written = 0;
        body.AsSpan(0, body.Length - 1).CopyTo(line);
        written += body.Length - 1;
        written += Encoding.ASCII.GetBytes(MacMarker, line.AsSpan(written));
        written += Encoding.ASCII.GetBytes(Convert.ToBase64String(mac), line.AsSpan(written));
        written += Encoding.ASCII.GetBytes("\"}\n", line.AsSpan(written));

        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path))!);
        using var stream = new FileStream(Path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
        stream.Write(line.AsSpan(0, written));
        stream.Flush(flushToDisk: true);
        return (sequence, mac);
    }

    /// <summary>
    /// Detects an entry that was appended but whose vault update never completed (a crash between the two
    /// writes): the last line follows the vault's recorded head and its MAC is valid. Returns its sequence and MAC
    /// so the next entry can chain from it instead of forking the chain.
    /// </summary>
    public (ulong Sequence, byte[] Mac)? FindUnanchoredTail(ReadOnlySpan<byte> key, ulong headSequence, ReadOnlySpan<byte> headMac)
    {
        var line = ReadLastLine();
        if (line is null || !TryParse(line, out var record) || record.Sequence != headSequence + 1
            || !string.Equals(record.Previous, Convert.ToBase64String(headMac), StringComparison.Ordinal))
        {
            return null;
        }

        var markerIndex = line.LastIndexOf(MacMarker, StringComparison.Ordinal);
        var mac = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(line[..markerIndex] + "}"));
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Convert.ToBase64String(mac)), Encoding.ASCII.GetBytes(record.Mac))
            ? (record.Sequence, mac)
            : null;
    }

    /// <summary>Reads every entry. Malformed lines are reported by <see cref="Verify"/>, and skipped here.</summary>
    public IReadOnlyList<AuditRecord> ReadAll()
    {
        var records = new List<AuditRecord>();
        foreach (var line in ReadLines())
        {
            if (TryParse(line, out var record))
            {
                records.Add(record);
            }
        }

        return records;
    }

    /// <summary>
    /// Checks every MAC, the <c>prev</c> links, sequence continuity, and that the last entry matches the
    /// head recorded in the vault (<paramref name="expectedSequence"/>, <paramref name="expectedHead"/>).
    /// </summary>
    public AuditVerification Verify(ReadOnlySpan<byte> key, ulong expectedSequence, ReadOnlySpan<byte> expectedHead)
    {
        var problems = new List<string>();
        var warnings = new List<string>();
        var previousMac = Convert.ToBase64String(GenesisMac);
        ulong previousSequence = 0;
        ulong headSequence = 0;
        string? headMac = null;
        var count = 0;
        var lineNumber = 0;

        foreach (var line in ReadLines())
        {
            lineNumber++;
            if (!TryParse(line, out var record))
            {
                problems.Add($"Line {lineNumber}: not a valid audit entry.");
                continue;
            }

            count++;
            var markerIndex = line.LastIndexOf(MacMarker, StringComparison.Ordinal);
            var body = Encoding.UTF8.GetBytes(line[..markerIndex] + "}");
            var expectedMac = Convert.ToBase64String(HMACSHA256.HashData(key, body));
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expectedMac), Encoding.ASCII.GetBytes(record.Mac)))
            {
                problems.Add($"Line {lineNumber} (seq {record.Sequence}): MAC mismatch, the entry was edited.");
            }

            if (record.Sequence != previousSequence + 1)
            {
                problems.Add($"Line {lineNumber}: sequence jumps from {previousSequence} to {record.Sequence}, entries were deleted or reordered.");
            }

            if (!string.Equals(record.Previous, previousMac, StringComparison.Ordinal))
            {
                problems.Add($"Line {lineNumber} (seq {record.Sequence}): chain link broken, the previous entry was removed or changed.");
            }

            previousMac = record.Mac;
            previousSequence = record.Sequence;
            headSequence = record.Sequence;
            headMac = record.Mac;
        }

        var expectedHeadText = Convert.ToBase64String(expectedHead);
        if (headSequence == expectedSequence)
        {
            if (expectedSequence > 0 && !string.Equals(headMac, expectedHeadText, StringComparison.Ordinal))
            {
                problems.Add("The last entry does not match the head recorded in the vault.");
            }
        }
        else if (headSequence < expectedSequence)
        {
            problems.Add($"The log ends at seq {headSequence} but the vault recorded seq {expectedSequence}: the log was truncated.");
        }
        else if (headSequence == expectedSequence + 1)
        {
            warnings.Add($"Entry seq {headSequence} is newer than the head recorded in the vault (an interrupted write). It is MAC-valid but not anchored.");
        }
        else
        {
            problems.Add($"The log continues to seq {headSequence} past the vault's recorded seq {expectedSequence}: the vault file was rolled back.");
        }

        return new AuditVerification(problems.Count == 0, count, problems, warnings);
    }

    private IEnumerable<string> ReadLines()
    {
        if (!File.Exists(Path))
        {
            yield break;
        }

        using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            if (line.Length > 0)
            {
                yield return line;
            }
        }
    }

    private string? ReadLastLine()
    {
        if (!File.Exists(Path))
        {
            return null;
        }

        // Audit lines are short; reading the last 16 KiB is enough to find the final complete line.
        using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var length = (int)Math.Min(stream.Length, 16 * 1024);
        stream.Seek(-length, SeekOrigin.End);
        var buffer = new byte[length];
        stream.ReadExactly(buffer);
        var lines = Encoding.UTF8.GetString(buffer).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        return lines.Length == 0 ? null : lines[^1].TrimEnd('\r');
    }

    private static byte[] BuildBody(AuditEvent e, ulong sequence, DateTimeOffset timestamp, bool deferred, ReadOnlySpan<byte> previousMac)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("seq", sequence);
            writer.WriteString("ts", timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture));
            writer.WriteString("action", e.Action);
            writer.WriteStartArray("secrets");
            foreach (var name in e.Secrets)
            {
                writer.WriteStringValue(name);
            }

            writer.WriteEndArray();
            writer.WriteString("result", e.Result);
            if (e.Detail is not null)
            {
                writer.WriteString("detail", e.Detail);
            }

            if (e.Process is { } p)
            {
                writer.WriteNumber("pid", p.Pid);
                WriteOptional(writer, "process", p.Path);
                if (p.ParentPid is { } parent)
                {
                    writer.WriteNumber("parentPid", parent);
                }

                WriteOptional(writer, "parentProcess", p.ParentPath);
            }

            if (deferred)
            {
                writer.WriteBoolean("deferred", true);
            }

            writer.WriteString("prev", Convert.ToBase64String(previousMac));
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static void WriteOptional(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is not null)
        {
            writer.WriteString(name, value);
        }
    }

    private static bool TryParse(string line, out AuditRecord record)
    {
        record = null!;
        if (line.LastIndexOf(MacMarker, StringComparison.Ordinal) < 0)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            var secrets = root.TryGetProperty("secrets", out var s) && s.ValueKind == JsonValueKind.Array
                ? s.EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToArray()
                : [];
            record = new AuditRecord(
                root.GetProperty("seq").GetUInt64(),
                DateTimeOffset.Parse(root.GetProperty("ts").GetString()!, System.Globalization.CultureInfo.InvariantCulture),
                root.GetProperty("action").GetString()!,
                secrets,
                root.GetProperty("result").GetString()!,
                OptionalString(root, "detail"),
                root.TryGetProperty("pid", out var pid) ? pid.GetInt32() : null,
                OptionalString(root, "process"),
                root.TryGetProperty("parentPid", out var ppid) ? ppid.GetInt32() : null,
                OptionalString(root, "parentProcess"),
                root.TryGetProperty("deferred", out var d) && d.GetBoolean(),
                root.GetProperty("prev").GetString()!,
                root.GetProperty("mac").GetString()!);
            return true;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            // Verify() reports unparsable lines as tampering; ReadAll() skips them for display.
            return false;
        }
    }

    private static string? OptionalString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
