using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Hush.Core.Crypto;
using Hush.Core.Keys;

namespace Hush.Core.Vault;

/// <summary>
/// Reads and writes the binary vault format (see docs/vault-format.md). All integers are little-endian,
/// strings are a u16 byte length followed by UTF-8, blobs are a u32 length followed by bytes. The last
/// 32 bytes are HMAC-SHA256 over everything before them, keyed by HKDF(DEK, salt, "hush/header-mac/v1").
/// </summary>
public static class VaultCodec
{
    /// <summary>File magic: <c>HUSHVLT\0</c>.</summary>
    public static ReadOnlySpan<byte> Magic => "HUSHVLT\0"u8;

    /// <summary>The format version this build writes and reads.</summary>
    public const ushort CurrentVersion = 1;

    /// <summary>Size of the trailing MAC.</summary>
    public const int MacSize = 32;

    private const int MaxString = 4096;
    private const int MaxBlob = 1 << 20;
    private const int MaxEntries = 100_000;

    /// <summary>AAD for an entry: vault_id || entry_id || entry_version.</summary>
    public static byte[] EntryAad(Guid vaultId, Guid entryId, uint version)
    {
        var aad = new byte[36];
        vaultId.TryWriteBytes(aad.AsSpan(0, 16));
        entryId.TryWriteBytes(aad.AsSpan(16, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(32), version);
        return aad;
    }

    /// <summary>AAD for a wrapped DEK: "hush/wrap/v1" || vault_id || kind.</summary>
    public static byte[] WrapAad(Guid vaultId, WrapKind kind)
    {
        var label = "hush/wrap/v1"u8;
        var aad = new byte[label.Length + 17];
        label.CopyTo(aad);
        vaultId.TryWriteBytes(aad.AsSpan(label.Length, 16));
        aad[^1] = (byte)kind;
        return aad;
    }

    /// <summary>AAD for the wrapped audit key: "hush/audit-key/v1" || vault_id.</summary>
    public static byte[] AuditKeyAad(Guid vaultId)
    {
        var label = "hush/audit-key/v1"u8;
        var aad = new byte[label.Length + 16];
        label.CopyTo(aad);
        vaultId.TryWriteBytes(aad.AsSpan(label.Length, 16));
        return aad;
    }

    /// <summary>Derives the MAC key from the DEK.</summary>
    public static SecureBuffer DeriveMacKey(ReadOnlySpan<byte> dek, ReadOnlySpan<byte> salt) => Kdf.Derive(dek, salt, Kdf.HeaderMacInfo);

    /// <summary>Serializes a document and appends its MAC.</summary>
    public static byte[] Write(VaultDocument document, ReadOnlySpan<byte> dek)
    {
        ArgumentNullException.ThrowIfNull(document);
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(Magic);
            writer.Write(document.FormatVersion);
            writer.Write((ushort)document.Flags);
            WriteGuid(writer, document.VaultId);
            WriteFixed(writer, document.Salt, 32, "salt");
            WriteFixed(writer, document.Challenge, 32, "challenge");
            writer.Write(document.Created.ToUnixTimeMilliseconds());
            writer.Write(document.Updated.ToUnixTimeMilliseconds());
            writer.Write(document.Generation);
            writer.Write(document.AuditSequence);
            WriteFixed(writer, document.AuditHead, 32, "audit head");

            if (document.Factors is { } factors)
            {
                writer.Write((byte)1);
                writer.Write((byte)factors.SecondFactor);
                WriteString(writer, factors.HelloKeyName);
                WriteBlob(writer, factors.HelloPublicKey);
                WriteString(writer, factors.SecondFactorKeyName);
                WriteBlob(writer, factors.SealedSecondFactor);
                WriteString(writer, factors.DegradedReason ?? string.Empty);
            }
            else
            {
                writer.Write((byte)0);
            }

            WriteBlob(writer, document.WrappedAuditKey);

            writer.Write(checked((byte)document.WrappedKeys.Count));
            foreach (var wrapped in document.WrappedKeys)
            {
                writer.Write((byte)wrapped.Kind);
                WriteBlob(writer, wrapped.Blob);
            }

            writer.Write(document.Entries.Count);
            foreach (var entry in document.Entries)
            {
                WriteGuid(writer, entry.Id);
                writer.Write(entry.Version);
                WriteString(writer, entry.Scope);
                WriteString(writer, entry.Name);
                writer.Write((byte)entry.Policy);
                writer.Write(entry.Created.ToUnixTimeMilliseconds());
                writer.Write(entry.Updated.ToUnixTimeMilliseconds());
                writer.Write(entry.LastUsed?.ToUnixTimeMilliseconds() ?? 0L);
                WriteBlob(writer, entry.Ciphertext);
            }
        }

        var body = stream.ToArray();
        var result = new byte[body.Length + MacSize];
        body.CopyTo(result, 0);
        using var macKey = DeriveMacKey(dek, document.Salt);
        HMACSHA256.HashData(macKey.Span, body, result.AsSpan(body.Length));
        return result;
    }

    /// <summary>
    /// Parses a vault file without verifying the MAC (the MAC key needs the DEK). Callers must call
    /// <see cref="VerifyMac"/> once they hold the DEK.
    /// </summary>
    public static VaultDocument Read(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < Magic.Length + 2 + MacSize || !bytes[..Magic.Length].SequenceEqual(Magic))
        {
            throw new HushException(HushErrorCode.VaultCorrupt, "This is not a Hush vault file.");
        }

        var reader = new SpanReader(bytes[..^MacSize]);
        reader.Skip(Magic.Length);
        var version = reader.U16();
        if (version != CurrentVersion)
        {
            throw new HushException(HushErrorCode.VaultCorrupt, $"Vault format version {version} is not supported by this build of Hush (expects {CurrentVersion}).");
        }

        var flags = (VaultAttributes)reader.U16();
        var vaultId = reader.Guid();
        var salt = reader.Fixed(32);
        var challenge = reader.Fixed(32);
        var created = DateTimeOffset.FromUnixTimeMilliseconds(reader.I64());
        var updated = DateTimeOffset.FromUnixTimeMilliseconds(reader.I64());
        var generation = reader.U32();
        var auditSequence = reader.U64();
        var auditHead = reader.Fixed(32);

        FactorInfo? factors = null;
        var hasFactors = reader.U8();
        if (hasFactors == 1)
        {
            var kind = (SecondFactorKind)reader.U8();
            if (!Enum.IsDefined(kind))
            {
                throw new HushException(HushErrorCode.VaultCorrupt, "The vault uses an unknown second-factor type.");
            }

            var helloName = reader.String();
            var helloPublic = reader.Blob();
            var factorKeyName = reader.String();
            var sealedFactor = reader.Blob();
            var degraded = reader.String();
            factors = new FactorInfo(kind, helloName, helloPublic, factorKeyName, sealedFactor, degraded.Length == 0 ? null : degraded);
        }
        else if (hasFactors != 0)
        {
            throw new HushException(HushErrorCode.VaultCorrupt, "The vault factor block is malformed.");
        }

        var wrappedAuditKey = reader.Blob();
        var wrappedCount = reader.U8();
        var wrapped = new List<WrappedKey>(wrappedCount);
        for (var i = 0; i < wrappedCount; i++)
        {
            var kind = (WrapKind)reader.U8();
            wrapped.Add(new WrappedKey(kind, reader.Blob()));
        }

        var entryCount = reader.I32();
        if (entryCount is < 0 or > MaxEntries)
        {
            throw new HushException(HushErrorCode.VaultCorrupt, "The vault entry table is malformed.");
        }

        var entries = new List<VaultEntry>(entryCount);
        for (var i = 0; i < entryCount; i++)
        {
            var id = reader.Guid();
            var entryVersion = reader.U32();
            var scope = reader.String();
            var name = reader.String();
            var policy = (SecretPolicy)reader.U8();
            if (!Enum.IsDefined(policy))
            {
                throw new HushException(HushErrorCode.VaultCorrupt, "A vault entry has an unknown policy.");
            }

            var entryCreated = DateTimeOffset.FromUnixTimeMilliseconds(reader.I64());
            var entryUpdated = DateTimeOffset.FromUnixTimeMilliseconds(reader.I64());
            var lastUsedMs = reader.I64();
            var ciphertext = reader.Blob();
            entries.Add(new VaultEntry(
                id,
                entryVersion,
                scope,
                name,
                policy,
                entryCreated,
                entryUpdated,
                lastUsedMs == 0 ? null : DateTimeOffset.FromUnixTimeMilliseconds(lastUsedMs),
                ciphertext));
        }

        if (!reader.AtEnd)
        {
            throw new HushException(HushErrorCode.VaultCorrupt, "The vault file has unexpected trailing data.");
        }

        return new VaultDocument
        {
            FormatVersion = version,
            Flags = flags,
            VaultId = vaultId,
            Salt = salt,
            Challenge = challenge,
            Created = created,
            Updated = updated,
            Generation = generation,
            AuditSequence = auditSequence,
            AuditHead = auditHead,
            Factors = factors,
            WrappedAuditKey = wrappedAuditKey,
            WrappedKeys = wrapped,
            Entries = entries,
        };
    }

    /// <summary>Verifies the trailing MAC with the DEK; throws on mismatch.</summary>
    public static void VerifyMac(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> dek, ReadOnlySpan<byte> salt)
    {
        if (bytes.Length < MacSize)
        {
            throw new HushException(HushErrorCode.VaultCorrupt, "The vault file is truncated.");
        }

        Span<byte> expected = stackalloc byte[MacSize];
        using var macKey = DeriveMacKey(dek, salt);
        HMACSHA256.HashData(macKey.Span, bytes[..^MacSize], expected);
        if (!CryptographicOperations.FixedTimeEquals(expected, bytes[^MacSize..]))
        {
            throw new HushException(HushErrorCode.TamperDetected, "The vault header MAC does not match: the file was modified outside Hush.");
        }
    }

    private static void WriteGuid(BinaryWriter writer, Guid value)
    {
        Span<byte> bytes = stackalloc byte[16];
        value.TryWriteBytes(bytes);
        writer.Write(bytes);
    }

    private static void WriteFixed(BinaryWriter writer, byte[] value, int length, string what)
    {
        if (value.Length != length)
        {
            throw new ArgumentException($"The {what} must be {length} bytes.", nameof(value));
        }

        writer.Write(value);
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length > MaxString)
        {
            throw new ArgumentException("String too long for the vault format.", nameof(value));
        }

        writer.Write((ushort)bytes.Length);
        writer.Write(bytes);
    }

    private static void WriteBlob(BinaryWriter writer, byte[] value)
    {
        if (value.Length > MaxBlob)
        {
            throw new ArgumentException("Blob too large for the vault format.", nameof(value));
        }

        writer.Write(value.Length);
        writer.Write(value);
    }

    private ref struct SpanReader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _position;

        public readonly bool AtEnd => _position == _data.Length;

        public void Skip(int count) => Take(count);

        public byte U8() => Take(1)[0];

        public ushort U16() => BinaryPrimitives.ReadUInt16LittleEndian(Take(2));

        public uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));

        public int I32() => BinaryPrimitives.ReadInt32LittleEndian(Take(4));

        public ulong U64() => BinaryPrimitives.ReadUInt64LittleEndian(Take(8));

        public long I64() => BinaryPrimitives.ReadInt64LittleEndian(Take(8));

        public Guid Guid() => new(Take(16));

        public byte[] Fixed(int length) => Take(length).ToArray();

        public string String()
        {
            var length = U16();
            if (length > MaxString)
            {
                throw Corrupt();
            }

            return Encoding.UTF8.GetString(Take(length));
        }

        public byte[] Blob()
        {
            var length = I32();
            if (length is < 0 or > MaxBlob)
            {
                throw Corrupt();
            }

            return Take(length).ToArray();
        }

        private ReadOnlySpan<byte> Take(int count)
        {
            if (count < 0 || _position + count > _data.Length)
            {
                throw Corrupt();
            }

            var slice = _data.Slice(_position, count);
            _position += count;
            return slice;
        }

        private static HushException Corrupt() => new(HushErrorCode.VaultCorrupt, "The vault file is truncated or malformed.");
    }
}
