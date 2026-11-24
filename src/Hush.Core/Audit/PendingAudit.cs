using System.Text.Json;
using Hush.Core.Interop;

namespace Hush.Core.Audit;

/// <summary>
/// Events that happen while no audit key is available (for example a cancelled unlock) are written here
/// unauthenticated, then folded into the HMAC chain, marked <c>deferred</c>, at the next unlock.
/// </summary>
public static class PendingAudit
{
    /// <summary>Appends an event to the pending file.</summary>
    public static void Append(string path, AuditEvent auditEvent, DateTimeOffset timestamp)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("ts", timestamp.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
            writer.WriteString("action", auditEvent.Action);
            writer.WriteStartArray("secrets");
            foreach (var name in auditEvent.Secrets)
            {
                writer.WriteStringValue(name);
            }

            writer.WriteEndArray();
            writer.WriteString("result", auditEvent.Result);
            if (auditEvent.Detail is not null)
            {
                writer.WriteString("detail", auditEvent.Detail);
            }

            if (auditEvent.Process is { } p)
            {
                writer.WriteNumber("pid", p.Pid);
                if (p.Path is not null)
                {
                    writer.WriteString("process", p.Path);
                }

                if (p.ParentPid is { } parent)
                {
                    writer.WriteNumber("parentPid", parent);
                }

                if (p.ParentPath is not null)
                {
                    writer.WriteString("parentProcess", p.ParentPath);
                }
            }

            writer.WriteEndObject();
        }

        buffer.WriteByte((byte)'\n');
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
                buffer.Position = 0;
                buffer.CopyTo(stream);
                return;
            }
            catch (IOException) when (attempt < 20)
            {
                Thread.Sleep(25);
            }
        }
    }

    /// <summary>Reads and deletes all pending events. Lines that cannot be parsed are kept as an error event.</summary>
    public static IReadOnlyList<(DateTimeOffset Timestamp, AuditEvent Event)> Drain(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        var result = new List<(DateTimeOffset, AuditEvent)>();
        foreach (var line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var ts = DateTimeOffset.Parse(root.GetProperty("ts").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
                var secrets = root.TryGetProperty("secrets", out var s) ? s.EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToArray() : [];
                ProcessIdentity? process = root.TryGetProperty("pid", out var pid)
                    ? new ProcessIdentity(
                        pid.GetInt32(),
                        root.TryGetProperty("process", out var pp) ? pp.GetString() : null,
                        root.TryGetProperty("parentPid", out var ppid) ? ppid.GetInt32() : null,
                        root.TryGetProperty("parentProcess", out var ppp) ? ppp.GetString() : null)
                    : null;
                result.Add((ts, new AuditEvent(
                    root.GetProperty("action").GetString()!,
                    secrets,
                    root.GetProperty("result").GetString()!,
                    root.TryGetProperty("detail", out var d) ? d.GetString() : null,
                    process)));
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                result.Add((DateTimeOffset.UtcNow, new AuditEvent("audit.pending-unreadable", [], "error", "A pending audit line could not be parsed.", null)));
            }
        }

        File.Delete(path);
        return result;
    }
}
