using System.Windows;
using Hush.Core;

namespace Hush.App.Infrastructure;

/// <summary>Runs UI actions and turns expected failures into friendly dialogs.</summary>
internal static class Ui
{
    /// <summary>Runs <paramref name="action"/>; Hush errors become a message box, cancellations are silent.</summary>
    public static async Task<bool> TryAsync(Window owner, Func<Task> action)
    {
        try
        {
            await action();
            return true;
        }
        catch (HushException ex) when (ex.Code == HushErrorCode.HelloCancelled)
        {
            return false;
        }
        catch (HushException ex)
        {
            MessageBox.Show(owner, ex.Message, "Hush", MessageBoxButton.OK, ex.Code == HushErrorCode.TamperDetected ? MessageBoxImage.Error : MessageBoxImage.Warning);
            return false;
        }
        catch (IOException ex)
        {
            MessageBox.Show(owner, ex.Message, "Hush", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
    }

    /// <summary>A short relative time ("3 min ago").</summary>
    public static string Relative(DateTimeOffset? time)
    {
        if (time is null)
        {
            return "never";
        }

        var age = DateTimeOffset.UtcNow - time.Value;
        return age.TotalMinutes < 1 ? "just now"
            : age.TotalHours < 1 ? $"{(int)age.TotalMinutes} min ago"
            : age.TotalDays < 1 ? $"{(int)age.TotalHours} h ago"
            : $"{(int)age.TotalDays} d ago";
    }
}
