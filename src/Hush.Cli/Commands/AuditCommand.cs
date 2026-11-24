using System.Globalization;
using Hush.Cli.Terminal;
using Hush.Core.Audit;

namespace Hush.Cli.Commands;

/// <summary><c>hush audit</c>: show the log; <c>--verify</c> checks the HMAC chain.</summary>
internal static class AuditCommand
{
    public static async Task<int> RunAsync(CliServices s, bool verify, int last, string? filter, CancellationToken ct)
    {
        var t = s.Terminal;
        var records = new AuditLog(s.Paths.AuditLog).ReadAll()
            .Where(r => filter is null
                || r.Action.Contains(filter, StringComparison.OrdinalIgnoreCase)
                || r.Secrets.Any(n => n.Contains(filter, StringComparison.OrdinalIgnoreCase))
                || (r.Process?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
                || (r.ParentProcess?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false))
            .ToList();

        foreach (var r in records.Skip(Math.Max(0, records.Count - last)))
        {
            var time = r.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            var result = r.Result == "ok" ? r.Result : t.Yellow(r.Result);
            var secrets = r.Secrets.Count == 0 ? string.Empty : " " + string.Join(", ", r.Secrets);
            var process = r.Process is null ? string.Empty : $"  {Path.GetFileName(r.Process)}#{r.Pid}";
            var parent = r.ParentProcess is null ? string.Empty : $" <- {Path.GetFileName(r.ParentProcess)}#{r.ParentPid}";
            t.Out.WriteLine($"{t.Dim($"{r.Sequence,5}")} {time}  {r.Action,-16} {result,-6}{secrets}{t.Dim(process + parent)}{(r.Detail is null ? string.Empty : t.Dim($"  ({r.Detail})"))}{(r.Deferred ? t.Dim(" [deferred]") : string.Empty)}");
        }

        if (records.Count == 0)
        {
            t.Out.WriteLine(filter is null ? "The audit log is empty." : "No entries match.");
        }

        if (!verify)
        {
            return 0;
        }

        var verification = await s.Session.VerifyAuditAsync(ct).ConfigureAwait(false);
        t.Out.WriteLine();
        foreach (var warning in verification.Warnings)
        {
            t.Out.WriteLine(t.Yellow("warning: ") + warning);
        }

        if (verification.IsValid)
        {
            t.Out.WriteLine(t.Green($"Audit chain intact: {verification.EntryCount} entries, MACs and links verified, head matches the vault."));
            return 0;
        }

        t.Out.WriteLine(t.Red($"Audit chain BROKEN ({verification.Problems.Count} problem(s)):"));
        foreach (var problem in verification.Problems)
        {
            t.Out.WriteLine("  " + problem);
        }

        return 1;
    }
}
