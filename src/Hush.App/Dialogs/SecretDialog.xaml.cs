using System.Windows;
using Hush.App.Infrastructure;
using Hush.App.Views;
using Hush.Core;
using Hush.Core.Manifest;
using Hush.Core.Vault;

namespace Hush.App.Dialogs;

/// <summary>Add or edit a secret. Editing leaves the value unchanged unless a new one is typed.</summary>
internal sealed partial class SecretDialog : Window
{
    private readonly AppServices _services;
    private readonly SecretRow? _existing;

    public SecretDialog(AppServices services, SecretRow? existing)
    {
        _services = services;
        _existing = existing;
        InitializeComponent();
        if (existing is null)
        {
            RevealButton.Visibility = Visibility.Collapsed;
            Loaded += (_, _) => NameBox.Focus();
            return;
        }

        Title = "Edit secret";
        Heading.Text = $"Edit {existing.Ref}";
        NameBox.Text = existing.Name;
        NameBox.IsReadOnly = true;
        ScopeBox.Text = existing.Scope;
        ScopeBox.IsReadOnly = true;
        PolicyBox.SelectedIndex = existing.Policy == SecretPolicy.AlwaysPrompt ? 1 : 0;
        ValueLabel.Content = "_New value (leave empty to keep the current one)";
        Loaded += (_, _) => ValueBox.Focus();
    }

    private SecretPolicy Policy => PolicyBox.SelectedIndex == 1 ? SecretPolicy.AlwaysPrompt : SecretPolicy.Session;

    private async void OnReveal(object sender, RoutedEventArgs e)
    {
        if (_existing is null)
        {
            return;
        }

        await Ui.TryAsync(this, async () =>
        {
            var values = await _services.Session.RevealAsync([new EnvBinding(_existing.Name, _existing.Ref, false)], "tray app: reveal", requirePresence: true, CancellationToken.None);
            RevealedBox.Text = values.Single().Value;
            RevealedBox.IsReadOnly = true;
            RevealedBox.Visibility = Visibility.Visible;
            ValueBox.Visibility = Visibility.Collapsed;
            RevealButton.IsEnabled = false;
            ValueHint.Text = "Revealed after Windows Hello confirmation. Close this dialog to hide it.";
        });
    }

    private async void OnSave(object sender, RoutedEventArgs e)
    {
        var value = ValueBox.Password;
        SecretRef reference;
        try
        {
            reference = SecretRef.Parse(NameBox.Text.Trim(), ScopeBox.Text.Trim());
        }
        catch (HushException ex)
        {
            MessageBox.Show(this, ex.Message, "Hush", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_existing is null && value.Length == 0)
        {
            MessageBox.Show(this, "Enter a value.", "Hush", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var saved = await Ui.TryAsync(this, async () =>
        {
            if (value.Length > 0)
            {
                await _services.Session.SetAsync(reference, value, Policy, CancellationToken.None);
            }
            else if (_existing is not null && _existing.Policy != Policy)
            {
                await _services.Session.SetPolicyAsync(reference, Policy, CancellationToken.None);
            }
        });

        ValueBox.Clear();
        if (saved)
        {
            DialogResult = true;
        }
    }
}
