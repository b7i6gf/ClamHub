namespace ClamAVGui.Core;

/// <summary>
/// Runs freshclam signature updates and queries the installed ClamAV version.
/// Replaces the UPDATE / UPDATESTART sections of the old batch scripts.
/// Called from: MainWindow (update button, optional update on start, version label).
/// </summary>
public static class UpdateManager
{
    /// <summary>True while an update is running, prevents parallel freshclam runs.</summary>
    public static bool UpdateInProgress { get; private set; }

    /// <summary>
    /// Runs freshclam with the portable config and streams its output.
    /// freshclam.conf contains NotifyClamd, so a running daemon reloads the
    /// new signatures automatically after the update.
    /// Called from: MainWindow update button and startup (UpdateOnStart setting).
    /// </summary>
    public static async Task<bool> RunUpdateAsync(Action<string> onOutput, CancellationToken cancel = default)
    {
        if (UpdateInProgress)
        {
            onOutput("An update is already running.");
            return false;
        }

        UpdateInProgress = true;
        try
        {
            onOutput("Starting signature update (freshclam)...");
            var result = await ProcessRunner.RunAsync(
                AppPaths.FreshClamExe,
                $"--config-file=\"{AppPaths.FreshClamConf}\"",
                onOutput,
                cancel);

            if (!result.Started)
            {
                onOutput(result.StartError ?? "freshclam could not be started.");
                return false;
            }

            onOutput(result.ExitCode == 0
                ? "Update finished successfully."
                : $"freshclam exited with code {result.ExitCode}. Check Logs\\freshclam.log.");
            return result.ExitCode == 0;
        }
        finally
        {
            UpdateInProgress = false;
        }
    }

    /// <summary>
    /// Returns the ClamAV version string (clamscan --version) or null on error.
    /// Called from: MainWindow to fill the version label on startup and after updates.
    /// </summary>
    public static async Task<string?> GetVersionAsync()
    {
        string? version = null;
        var result = await ProcessRunner.RunAsync(
            AppPaths.ClamScanExe,
            "--version",
            line => version ??= line);
        return result.Started && result.ExitCode == 0 ? version : null;
    }
}
