using System.Text;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using Hush.Core.Migration;

namespace Hush.App.Dialogs;

/// <summary>Shows what a migration will do, with secret values redacted, before anything changes.</summary>
internal sealed partial class MigrationPreviewWindow : Window
{
    public MigrationPreviewWindow(MigrationPlan plan)
    {
        InitializeComponent();
        SummaryText.Text = $"{plan.Secrets.Count} secret(s) will move into the vault and {plan.Changes.Count} file(s) will change. Originals are backed up; 'Undo last migration' restores them.";

        var changes = new StringBuilder();
        changes.AppendLine("Secrets to vault:");
        foreach (var secret in plan.Secrets)
        {
            changes.Append("  ").Append(secret.Target.ToString()).Append("   ").Append(MigrationPlan.RedactValue(secret.Value)).Append("   from ").AppendLine(secret.Source);
        }

        changes.AppendLine().AppendLine("Files:");
        foreach (var change in plan.Changes)
        {
            changes.Append(change.Original is null ? "  create  " : "  modify  ").AppendLine(change.Path).Append("          ").AppendLine(change.Description);
        }

        if (plan.Notes.Count > 0)
        {
            changes.AppendLine().AppendLine("Notes:");
            foreach (var note in plan.Notes)
            {
                changes.AppendLine("  ! " + note);
            }
        }

        ChangesText.Text = changes.ToString();
        DiffBox.Document = BuildDiffDocument(plan.RenderDiff());
    }

    private static FlowDocument BuildDiffDocument(string diff)
    {
        var added = new SolidColorBrush(Color.FromArgb(0x40, 0x3F, 0xB9, 0x50));
        var removed = new SolidColorBrush(Color.FromArgb(0x40, 0xF8, 0x51, 0x49));
        var header = new SolidColorBrush(Color.FromArgb(0x30, 0x7C, 0x6C, 0xFF));
        var document = new FlowDocument { PagePadding = new Thickness(8), PageWidth = 4000 };
        foreach (var line in diff.Split('\n'))
        {
            var paragraph = new Paragraph(new Run(line)) { Margin = new Thickness(0) };
            if (line.StartsWith("@@", StringComparison.Ordinal) || line.StartsWith("---", StringComparison.Ordinal) || line.StartsWith("+++", StringComparison.Ordinal))
            {
                paragraph.Background = header;
            }
            else if (line.StartsWith('+'))
            {
                paragraph.Background = added;
            }
            else if (line.StartsWith('-'))
            {
                paragraph.Background = removed;
            }

            document.Blocks.Add(paragraph);
        }

        return document;
    }

    private void OnMigrate(object sender, RoutedEventArgs e) => DialogResult = true;
}
