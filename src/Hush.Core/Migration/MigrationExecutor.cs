using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Hush.Core.Vault;

namespace Hush.Core.Migration;

/// <summary>Where migrated secrets go (the session broker, or a vault directly in tests).</summary>
public interface ISecretSink
{
    /// <summary>Stores the secrets.</summary>
    Task StoreAsync(IReadOnlyList<PlannedSecret> secrets, CancellationToken cancellationToken);

    /// <summary>Deletes secrets added by a migration that is being undone.</summary>
    Task RemoveAsync(IReadOnlyList<SecretRef> secrets, CancellationToken cancellationToken);
}

/// <summary>One file touched by a migration.</summary>
public sealed record JournalFile(string Path, string? Backup, string AfterHash, bool Applied);

/// <summary>The record of a migration run, stored next to its backups.</summary>
public sealed record MigrationJournal
{
    /// <summary>When the run started.</summary>
    public required DateTimeOffset Created { get; init; }

    /// <summary>Files, with their backup file names (null if the file was created by the run).</summary>
    public required IReadOnlyList<JournalFile> Files { get; init; }

    /// <summary>Secrets the run added to the vault.</summary>
    public required IReadOnlyList<string> Secrets { get; init; }

    /// <summary>When the run was undone, if it was.</summary>
    public DateTimeOffset? UndoneAt { get; init; }
}

/// <summary>Outcome of <see cref="MigrationExecutor.UndoAsync"/>.</summary>
public sealed record UndoResult(string BackupDirectory, IReadOnlyList<string> Restored, IReadOnlyList<string> Deleted, IReadOnlyList<string> RemovedSecrets);

/// <summary>
/// Applies a plan: vault first (so a failure leaves files untouched), then timestamped backups, then atomic
/// file writes, with a journal that <c>hush migrate --undo</c> uses to restore the last run.
/// </summary>
public sealed class MigrationExecutor
{
    private const string JournalName = "journal.json";
    private readonly HushPaths _paths;
    private readonly TimeProvider _time;

    /// <summary>Creates an executor that keeps backups under <see cref="HushPaths.Backups"/>.</summary>
    public MigrationExecutor(HushPaths paths, TimeProvider? time = null)
    {
        _paths = paths;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Applies <paramref name="plan"/>. Returns the backup directory.</summary>
    public async Task<string> ApplyAsync(MigrationPlan plan, ISecretSink sink, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(sink);
        foreach (var change in plan.Changes)
        {
            var current = File.Exists(change.Path) ? await File.ReadAllTextAsync(change.Path, cancellationToken).ConfigureAwait(false) : null;
            if (!string.Equals(current, change.Original, StringComparison.Ordinal))
            {
                throw new HushException(HushErrorCode.MigrationFailed, $"{change.Path} changed since the plan was made. Run 'hush migrate' again.");
            }
        }

        if (plan.Secrets.Count > 0)
        {
            await sink.StoreAsync(plan.Secrets, cancellationToken).ConfigureAwait(false);
        }

        var now = _time.GetUtcNow();
        var directory = Path.Combine(_paths.Backups, now.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(directory);
        var files = new List<JournalFile>();
        for (var i = 0; i < plan.Changes.Count; i++)
        {
            var change = plan.Changes[i];
            string? backup = null;
            if (change.Original is not null)
            {
                backup = $"{i + 1:D4}-{Path.GetFileName(change.Path)}.bak";
                File.Copy(change.Path, Path.Combine(directory, backup));
            }

            files.Add(new JournalFile(change.Path, backup, Hash(change.Updated), Applied: false));
        }

        var journal = new MigrationJournal { Created = now, Files = files, Secrets = plan.Secrets.Select(s => s.Target.ToString()).ToList() };
        SaveJournal(directory, journal);

        for (var i = 0; i < plan.Changes.Count; i++)
        {
            var change = plan.Changes[i];
            VaultStore.WriteAtomic(change.Path, Encoding.UTF8.GetBytes(change.Updated));
            files[i] = files[i] with { Applied = true };
            SaveJournal(directory, journal with { Files = files });
        }

        return directory;
    }

    /// <summary>
    /// Restores the most recent migration that has not been undone: original files come back from the
    /// backups, files the migration created are deleted, and the secrets it added are removed from the vault.
    /// Refuses (unless <paramref name="force"/>) if a file was edited after the migration.
    /// </summary>
    public async Task<UndoResult> UndoAsync(ISecretSink sink, bool force, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sink);
        var (directory, journal) = LatestUndoable()
            ?? throw new HushException(HushErrorCode.MigrationFailed, "There is no migration to undo.");

        var applied = journal.Files.Where(f => f.Applied).ToList();
        if (!force)
        {
            foreach (var file in applied)
            {
                var current = File.Exists(file.Path) ? Hash(await File.ReadAllTextAsync(file.Path, cancellationToken).ConfigureAwait(false)) : null;
                if (current != file.AfterHash)
                {
                    throw new HushException(HushErrorCode.MigrationFailed, $"{file.Path} was edited after the migration. Re-run with --force to overwrite it with the backup.");
                }
            }
        }

        var restored = new List<string>();
        var deleted = new List<string>();
        foreach (var file in applied)
        {
            if (file.Backup is null)
            {
                File.Delete(file.Path);
                deleted.Add(file.Path);
            }
            else
            {
                VaultStore.WriteAtomic(file.Path, await File.ReadAllBytesAsync(Path.Combine(directory, file.Backup), cancellationToken).ConfigureAwait(false));
                restored.Add(file.Path);
            }
        }

        var secrets = journal.Secrets.Select(s => SecretRef.Parse(s)).ToList();
        if (secrets.Count > 0)
        {
            await sink.RemoveAsync(secrets, cancellationToken).ConfigureAwait(false);
        }

        SaveJournal(directory, journal with { UndoneAt = _time.GetUtcNow() });
        return new UndoResult(directory, restored, deleted, journal.Secrets);
    }

    /// <summary>The most recent migration that can still be undone, if any.</summary>
    public (string Directory, MigrationJournal Journal)? LatestUndoable()
    {
        if (!Directory.Exists(_paths.Backups))
        {
            return null;
        }

        foreach (var directory in Directory.EnumerateDirectories(_paths.Backups).OrderDescending(StringComparer.Ordinal))
        {
            var path = Path.Combine(directory, JournalName);
            if (!File.Exists(path))
            {
                continue;
            }

            var journal = JsonSerializer.Deserialize(File.ReadAllText(path), MigrationJsonContext.Default.MigrationJournal);
            if (journal is not null && journal.UndoneAt is null)
            {
                return (directory, journal);
            }
        }

        return null;
    }

    private static void SaveJournal(string directory, MigrationJournal journal) =>
        VaultStore.WriteAtomic(Path.Combine(directory, JournalName), JsonSerializer.SerializeToUtf8Bytes(journal, MigrationJsonContext.Default.MigrationJournal));

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}

/// <summary>Source-generated JSON metadata for migration journals.</summary>
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(MigrationJournal))]
internal sealed partial class MigrationJsonContext : JsonSerializerContext;
