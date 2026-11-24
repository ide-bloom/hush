using System.Text.Json;
using System.Text.Json.Serialization;
using Hush.Core.Vault;

namespace Hush.Core.Settings;

/// <summary>User settings stored in <c>%LOCALAPPDATA%\Hush\settings.json</c>.</summary>
public sealed record HushSettings
{
    /// <summary>Smallest allowed idle timeout.</summary>
    public const int MinIdleTimeoutMinutes = 1;

    /// <summary>Largest allowed idle timeout (one day).</summary>
    public const int MaxIdleTimeoutMinutes = 24 * 60;

    /// <summary>Minutes without use before the session broker locks the vault. Default 10.</summary>
    public int IdleTimeoutMinutes { get; init; } = 10;

    /// <summary>Lock when the machine sleeps or hibernates. Default true. Workstation lock always locks.</summary>
    public bool LockOnSleep { get; init; } = true;

    /// <summary>Project roots searched for <c>.env*</c> files by <c>hush scan</c>.</summary>
    public IReadOnlyList<string> ScanRoots { get; init; } = DefaultScanRoots();

    /// <summary>The default project roots: source, Projects, dev and code under the user profile.</summary>
    public static IReadOnlyList<string> DefaultScanRoots()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return [Path.Combine(home, "source"), Path.Combine(home, "Projects"), Path.Combine(home, "dev"), Path.Combine(home, "code")];
    }

    /// <summary>The idle timeout clamped to the allowed range.</summary>
    [JsonIgnore]
    public TimeSpan IdleTimeout => TimeSpan.FromMinutes(Math.Clamp(IdleTimeoutMinutes, MinIdleTimeoutMinutes, MaxIdleTimeoutMinutes));

    /// <summary>Loads settings, or defaults if the file does not exist.</summary>
    public static HushSettings Load(HushPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (!File.Exists(paths.Settings))
        {
            return new HushSettings();
        }

        try
        {
            var loaded = JsonSerializer.Deserialize(File.ReadAllText(paths.Settings), SettingsJsonContext.Default.HushSettings) ?? new HushSettings();
            return loaded with { ScanRoots = loaded.ScanRoots ?? DefaultScanRoots() };
        }
        catch (JsonException ex)
        {
            throw new HushException(HushErrorCode.InvalidInput, $"{paths.Settings} is not valid JSON: {ex.Message}", ex);
        }
    }

    /// <summary>Validates and saves settings atomically.</summary>
    public void Save(HushPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (IdleTimeoutMinutes is < MinIdleTimeoutMinutes or > MaxIdleTimeoutMinutes)
        {
            throw new HushException(HushErrorCode.InvalidInput, $"The idle timeout must be between {MinIdleTimeoutMinutes} and {MaxIdleTimeoutMinutes} minutes.");
        }

        paths.EnsureHome();
        VaultStore.WriteAtomic(paths.Settings, JsonSerializer.SerializeToUtf8Bytes(this, SettingsJsonContext.Default.HushSettings));
    }
}

/// <summary>Source-generated JSON metadata for settings (trimming and AOT safe).</summary>
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(HushSettings))]
internal sealed partial class SettingsJsonContext : JsonSerializerContext;
