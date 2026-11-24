using System.ComponentModel;
using System.Runtime.InteropServices;
using Hush.Core.Interop;

namespace Hush.Core.Vault;

/// <summary>Test seam for crash simulation during atomic writes.</summary>
public interface IAtomicWriteHooks
{
    /// <summary>Called after the temporary file is written and flushed, before it replaces the target.</summary>
    void AfterTempFileFlushed(string tempPath);
}

/// <summary>
/// File access for the vault: atomic replace (temp file, flush to disk, MoveFileEx with
/// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) and a cross-process writer lock.
/// </summary>
public sealed class VaultStore
{
    private const string TempSuffix = ".tmp-";
    private readonly IAtomicWriteHooks? _hooks;

    /// <summary>Creates a store for <paramref name="path"/>, locking with <paramref name="lockPath"/>.</summary>
    public VaultStore(string path, string lockPath, IAtomicWriteHooks? hooks = null)
    {
        Path = path;
        LockPath = lockPath;
        _hooks = hooks;
    }

    /// <summary>The vault file.</summary>
    public string Path { get; }

    /// <summary>The lock file.</summary>
    public string LockPath { get; }

    /// <summary>True if the vault file exists.</summary>
    public bool Exists => File.Exists(Path);

    /// <summary>Creates a store for the default paths.</summary>
    public static VaultStore For(HushPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return new VaultStore(paths.Vault, paths.VaultLock);
    }

    /// <summary>Reads the whole vault file.</summary>
    public byte[] ReadAll()
    {
        if (!Exists)
        {
            throw new HushException(HushErrorCode.VaultNotFound, "No vault found. Run 'hush init' first.");
        }

        return File.ReadAllBytes(Path);
    }

    /// <summary>Returns a value that changes whenever the file is replaced.</summary>
    public (DateTime LastWriteUtc, long Length) Stamp()
    {
        var info = new FileInfo(Path);
        return info.Exists ? (info.LastWriteTimeUtc, info.Length) : (DateTime.MinValue, -1);
    }

    /// <summary>
    /// Writes <paramref name="content"/> atomically: readers see either the old file or the new one,
    /// never a partial write, even if the process dies or the machine loses power mid-write.
    /// </summary>
    public void WriteAtomic(ReadOnlySpan<byte> content) => WriteAtomic(Path, content, _hooks);

    /// <summary>Atomic write to an arbitrary path (used for exports and migration targets).</summary>
    public static void WriteAtomic(string path, ReadOnlySpan<byte> content, IAtomicWriteHooks? hooks = null)
    {
        ArgumentNullException.ThrowIfNull(path);
        var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        var temp = path + TempSuffix + Guid.NewGuid().ToString("N")[..8];
        using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            stream.Write(content);
            stream.Flush(flushToDisk: true);
        }

        hooks?.AfterTempFileFlushed(temp);

        if (!NativeMethods.MoveFileEx(temp, path, NativeMethods.MOVEFILE_REPLACE_EXISTING | NativeMethods.MOVEFILE_WRITE_THROUGH))
        {
            var error = Marshal.GetLastPInvokeError();
            File.Delete(temp);
            throw new IOException($"Could not replace '{path}'.", new Win32Exception(error));
        }
    }

    /// <summary>Removes temporary files left behind by an interrupted write.</summary>
    public int CleanupStaleTempFiles()
    {
        var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path))!;
        if (!Directory.Exists(directory))
        {
            return 0;
        }

        var removed = 0;
        foreach (var temp in Directory.EnumerateFiles(directory, System.IO.Path.GetFileName(Path) + TempSuffix + "*"))
        {
            File.Delete(temp);
            removed++;
        }

        return removed;
    }

    /// <summary>Acquires the exclusive writer lock, waiting up to <paramref name="timeout"/>.</summary>
    public IDisposable AcquireLock(TimeSpan timeout)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(LockPath))!);
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            try
            {
                return new FileStream(LockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(25);
            }
            catch (IOException ex)
            {
                throw new HushException(HushErrorCode.Unknown, "Another Hush process is holding the vault lock. Try again.", ex);
            }
        }
    }
}
