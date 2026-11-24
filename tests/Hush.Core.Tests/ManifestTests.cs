using Hush.Core.Manifest;
using Hush.Core.Settings;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Core.Tests;

public sealed class ManifestTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    private const string Sample = """
        version = 1
        project = "shop"
        default_profile = "dev"

        [env]
        DATABASE_URL = "DATABASE_URL"
        OPENAI_API_KEY = "/OPENAI_API_KEY"
        STRIPE = "payments/STRIPE_KEY"

        [profiles.staging.env]
        DATABASE_URL = "DATABASE_URL.staging"
        """;

    [Fact]
    public void Resolves_scopes_and_fallbacks()
    {
        var manifest = ProjectManifest.Parse(Sample, "x/.hush.toml");
        var bindings = manifest.Resolve(null).ToDictionary(b => b.Variable);
        Assert.Equal(new SecretRef("shop", "DATABASE_URL"), bindings["DATABASE_URL"].Secret);
        Assert.True(bindings["DATABASE_URL"].FallbackToGlobal);
        Assert.Equal(new SecretRef(string.Empty, "OPENAI_API_KEY"), bindings["OPENAI_API_KEY"].Secret);
        Assert.False(bindings["OPENAI_API_KEY"].FallbackToGlobal);
        Assert.Equal(new SecretRef("payments", "STRIPE_KEY"), bindings["STRIPE"].Secret);
    }

    [Fact]
    public void Profiles_overlay_the_base_table()
    {
        var manifest = ProjectManifest.Parse(Sample, "x/.hush.toml");
        var staging = manifest.Resolve("staging").ToDictionary(b => b.Variable);
        Assert.Equal("DATABASE_URL.staging", staging["DATABASE_URL"].Secret.Name);
        Assert.Equal(3, staging.Count);
        Assert.Equal(HushErrorCode.ManifestInvalid, Assert.Throws<HushException>(() => manifest.Resolve("nope")).Code);
    }

    [Fact]
    public void Is_found_in_parent_directories()
    {
        _temp.Write(".hush.toml", Sample);
        var nested = _temp.Combine("src", "deep", "er");
        Directory.CreateDirectory(nested);
        Assert.Equal(_temp.Combine(".hush.toml"), ProjectManifest.Locate(nested));
        using var elsewhere = new TempDirectory();
        Assert.Null(ProjectManifest.Locate(elsewhere.Path));
    }

    [Fact]
    public void Project_defaults_to_the_directory_name()
    {
        var path = _temp.Write(Path.Combine("my app", ".hush.toml"), "[env]\nA = \"A\"\n");
        Assert.Equal("my-app", ProjectManifest.Load(path).Project);
    }

    [Theory]
    [InlineData("version = 2")]
    [InlineData("[env]\nA = 1")]
    [InlineData("env = \"x\"")]
    [InlineData("this is not toml")]
    [InlineData("[env]\nA = \"bad name!\"")]
    public void Invalid_manifests_are_rejected(string text)
    {
        var ex = Assert.Throws<HushException>(() => ProjectManifest.Parse(text, "m.toml"));
        Assert.True(ex.Code is HushErrorCode.ManifestInvalid or HushErrorCode.InvalidInput, ex.Code.ToString());
    }

    [Fact]
    public void Created_text_parses_and_add_mappings_preserves_existing_content()
    {
        var text = ProjectManifest.CreateText("shop", [new("A", "A")]);
        var updated = ProjectManifest.AddMappings(text, "env", [new("A", "IGNORED"), new("B", "B")]);
        Assert.Contains("# Hush project manifest", updated, StringComparison.Ordinal);
        var manifest = ProjectManifest.Parse(updated, ".hush.toml");
        Assert.Equal("A", manifest.Env["A"]);
        Assert.Equal("B", manifest.Env["B"]);

        var withProfile = ProjectManifest.AddMappings(updated, "profiles.prod.env", [new("A", "A.prod")]);
        Assert.Equal("A.prod", ProjectManifest.Parse(withProfile, ".hush.toml").Profiles["prod"]["A"]);
    }

    [Fact]
    public void Secret_spec_parses_names_and_mappings()
    {
        var plain = SecretSpec.Parse("A, B=TOKEN ,C=/GLOBAL", manifest: null);
        Assert.Equal(["A", "B", "C"], plain.Select(b => b.Variable));
        Assert.Equal("TOKEN", plain[1].Secret.Name);
        Assert.Equal(string.Empty, plain[2].Secret.Scope);

        var manifest = ProjectManifest.Parse(Sample, "x/.hush.toml");
        var scoped = SecretSpec.Parse("DB=DATABASE_URL", manifest);
        Assert.Equal(new SecretRef("shop", "DATABASE_URL"), scoped[0].Secret);
        Assert.True(scoped[0].FallbackToGlobal);
        Assert.Throws<HushException>(() => SecretSpec.Parse("=X", null));
    }

    [Fact]
    public void Settings_round_trip_and_validate()
    {
        var paths = _temp.HushPaths;
        Assert.Equal(10, HushSettings.Load(paths).IdleTimeoutMinutes);
        new HushSettings { IdleTimeoutMinutes = 25, LockOnSleep = false, ScanRoots = ["C:\\src"] }.Save(paths);
        var loaded = HushSettings.Load(paths);
        Assert.Equal(25, loaded.IdleTimeoutMinutes);
        Assert.False(loaded.LockOnSleep);
        Assert.Equal(["C:\\src"], loaded.ScanRoots);
        Assert.Throws<HushException>(() => new HushSettings { IdleTimeoutMinutes = 0 }.Save(paths));
    }
}
