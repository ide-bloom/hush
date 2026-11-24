using System.Windows;
using Forms = System.Windows.Forms;

namespace Hush.App.Infrastructure;

/// <summary>The notification-area icon: shows the lock state and offers Open, Unlock, Lock and Exit.</summary>
internal sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly System.Drawing.Icon _locked;
    private readonly System.Drawing.Icon _unlocked;
    private readonly Forms.ToolStripMenuItem _unlockItem;
    private readonly Forms.ToolStripMenuItem _lockItem;

    public TrayIcon(Action open, Action unlock, Action lockNow, Action exit)
    {
        _locked = LoadIcon("tray-locked.ico");
        _unlocked = LoadIcon("tray-unlocked.ico");
        _unlockItem = new Forms.ToolStripMenuItem("&Unlock", null, (_, _) => unlock());
        _lockItem = new Forms.ToolStripMenuItem("&Lock now", null, (_, _) => lockNow());
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(new Forms.ToolStripMenuItem("&Open Hush", null, (_, _) => open()) { Font = new System.Drawing.Font(menu.Font, System.Drawing.FontStyle.Bold) });
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(_unlockItem);
        menu.Items.Add(_lockItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(new Forms.ToolStripMenuItem("E&xit", null, (_, _) => exit()));

        _icon = new Forms.NotifyIcon
        {
            Icon = _locked,
            Text = "Hush: locked",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left)
            {
                open();
            }
        };
        Update(unlocked: false, degraded: false);
    }

    public void Update(bool unlocked, bool degraded)
    {
        _icon.Icon = unlocked ? _unlocked : _locked;
        var text = unlocked ? "Hush: unlocked" : "Hush: locked";
        _icon.Text = degraded ? text + " (degraded: no TPM)" : text;
        _unlockItem.Enabled = !unlocked;
        _lockItem.Enabled = unlocked;
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        _locked.Dispose();
        _unlocked.Dispose();
    }

    private static System.Drawing.Icon LoadIcon(string name)
    {
        var resource = Application.GetResourceStream(new Uri($"pack://application:,,,/Assets/{name}"))
            ?? throw new InvalidOperationException($"Missing tray icon resource {name}.");
        using var stream = resource.Stream;
        return new System.Drawing.Icon(stream);
    }
}
