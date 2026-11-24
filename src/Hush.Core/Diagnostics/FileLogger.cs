using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Hush.Core.Diagnostics;

/// <summary>
/// A minimal structured logger that writes JSON lines to <c>%LOCALAPPDATA%\Hush\logs\&lt;name&gt;-yyyyMMdd.log</c>.
/// Hush logs names, ids and outcomes only; the HUSH001 analyzer fails the build if a [Sensitive] value
/// reaches a logging call.
/// </summary>
public sealed class FileLogger : ILogger
{
    private static readonly Lock Gate = new();
    private readonly string _directory;
    private readonly string _name;
    private readonly LogLevel _minimum;

    /// <summary>Creates a logger writing under <paramref name="directory"/>.</summary>
    public FileLogger(string directory, string name, LogLevel minimum = LogLevel.Information)
    {
        _directory = directory;
        _name = name;
        _minimum = minimum;
    }

    /// <summary>A logger for <paramref name="name"/> in the default log folder.</summary>
    public static FileLogger For(HushPaths paths, string name)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var level = Environment.GetEnvironmentVariable("HUSH_LOG_LEVEL") is { } text && Enum.TryParse<LogLevel>(text, true, out var parsed) ? parsed : LogLevel.Information;
        return new FileLogger(paths.Logs, name, level);
    }

    /// <inheritdoc />
    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    /// <inheritdoc />
    public bool IsEnabled(LogLevel logLevel) => logLevel >= _minimum && logLevel != LogLevel.None;

    /// <inheritdoc />
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);
        if (!IsEnabled(logLevel))
        {
            return;
        }

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("ts", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            writer.WriteString("level", logLevel.ToString());
            writer.WriteString("event", eventId.Name ?? eventId.Id.ToString(CultureInfo.InvariantCulture));
            writer.WriteString("message", formatter(state, exception));
            if (state is IReadOnlyList<KeyValuePair<string, object?>> properties)
            {
                foreach (var (key, value) in properties)
                {
                    if (key != "{OriginalFormat}")
                    {
                        writer.WriteString(key, Convert.ToString(value, CultureInfo.InvariantCulture));
                    }
                }
            }

            if (exception is not null)
            {
                // Exception messages in Hush never contain secrets (see HushException), so they are safe to log.
                writer.WriteString("exception", exception.GetType().FullName);
                writer.WriteString("error", exception.Message);
            }

            writer.WriteEndObject();
        }

        buffer.WriteByte((byte)'\n');
        var path = Path.Combine(_directory, $"{_name}-{DateTime.UtcNow:yyyyMMdd}.log");
        lock (Gate)
        {
            try
            {
                Directory.CreateDirectory(_directory);
                using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                stream.Write(buffer.GetBuffer(), 0, (int)buffer.Length);
            }
            catch (IOException ex)
            {
                // Logging must never take Hush down; report on stderr instead of silently dropping it.
                Console.Error.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()).TrimEnd() + $" (log write failed: {ex.Message})");
            }
        }
    }
}
