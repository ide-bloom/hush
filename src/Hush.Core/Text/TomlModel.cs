using Tomlyn;
using Tomlyn.Model;
using Tomlyn.Serialization;

namespace Hush.Core.Text;

/// <summary>Trimming- and AOT-safe parsing of TOML into the untyped <see cref="TomlTable"/> model.</summary>
public static class TomlModel
{
    /// <summary>Parses <paramref name="text"/>; throws <see cref="TomlException"/> on syntax errors.</summary>
    public static TomlTable Parse(string text) =>
        TomlSerializer.Deserialize<TomlTable>(text, TomlModelContext.Default) ?? [];
}

/// <summary>Source-generated serializer metadata for the untyped TOML model.</summary>
[TomlSerializable(typeof(TomlTable))]
internal sealed partial class TomlModelContext : TomlSerializerContext;
