using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace ClamAVGui.Core;

/// <summary>
/// Controls the clamd daemon: status check (PING/PONG over TCP), start with
/// readiness wait, and clean shutdown (SHUTDOWN command with kill fallback).
/// Replaces the logic of the old Clamd.bat. The daemon listens on localhost
/// only (see ConfigManager generated clamd.conf).
/// Called from: MainWindow (buttons, startup, exit), later ScanEngine to decide
/// between clamdscan and clamscan.
/// </summary>
public static class DaemonController
{
    /// <summary>Process handle when this GUI instance started clamd itself.</summary>
    private static Process? _ownedProcess;

    /// <summary>True when this GUI started the daemon (used for StopDaemonOnExit).</summary>
    public static bool StartedByGui => _ownedProcess is { HasExited: false };

    /// <summary>
    /// Checks whether clamd is responding. Sends "zPING\0" and expects "PONG".
    /// More reliable than a plain port check because it proves the daemon has
    /// finished loading its signature database.
    /// Called from: MainWindow status refresh, StartAsync wait loop, ScanEngine.
    /// </summary>
    public static async Task<bool> IsRunningAsync(int timeoutMs = 2000)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = new CancellationTokenSource(timeoutMs);
            await client.ConnectAsync("127.0.0.1", SettingsManager.Current.ClamdPort, cts.Token);

            var stream = client.GetStream();
            var ping = Encoding.ASCII.GetBytes("zPING\0");
            await stream.WriteAsync(ping, cts.Token);

            var buffer = new byte[16];
            int read = await stream.ReadAsync(buffer, cts.Token);
            return Encoding.ASCII.GetString(buffer, 0, read).Contains("PONG");
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Starts clamd if it is not already running and waits until it answers
    /// PING (signature loading can take a while). Reports progress via onStatus.
    /// Called from: MainWindow start button and auto start on app launch.
    /// </summary>
    public static async Task<bool> StartAsync(Action<string>? onStatus = null, int timeoutSeconds = 60)
    {
        if (await IsRunningAsync())
        {
            onStatus?.Invoke("clamd is already running.");
            return true;
        }

        onStatus?.Invoke("Starting clamd...");
        _ownedProcess = ProcessRunner.StartDetached(
            AppPaths.ClamdExe,
            $"--config-file=\"{AppPaths.ClamdConf}\"",
            out var error);

        if (_ownedProcess == null)
        {
            onStatus?.Invoke($"Failed to start clamd: {error}");
            return false;
        }

        onStatus?.Invoke("Waiting for clamd to load the signature database...");
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        while (DateTime.UtcNow < deadline)
        {
            if (_ownedProcess.HasExited)
            {
                onStatus?.Invoke($"clamd exited early (code {_ownedProcess.ExitCode}). Check Logs\\clamd.log.");
                _ownedProcess = null;
                return false;
            }
            if (await IsRunningAsync(1000))
            {
                onStatus?.Invoke("clamd is ready.");
                return true;
            }
            await Task.Delay(1000);
        }

        onStatus?.Invoke("Timeout: clamd did not become ready. Check Logs\\clamd.log.");
        return false;
    }

    /// <summary>
    /// Stops clamd gracefully via the SHUTDOWN command, kill as fallback.
    /// Called from: MainWindow stop button and app exit (StopDaemonOnExit).
    /// </summary>
    public static async Task StopAsync(Action<string>? onStatus = null)
    {
        if (!await IsRunningAsync(1000))
        {
            onStatus?.Invoke("clamd is not running.");
            _ownedProcess = null;
            return;
        }

        onStatus?.Invoke("Sending SHUTDOWN to clamd...");
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", SettingsManager.Current.ClamdPort);
            var cmd = Encoding.ASCII.GetBytes("zSHUTDOWN\0");
            await client.GetStream().WriteAsync(cmd);
        }
        catch
        {
            // Connection refused means it is already going down, ignore.
        }

        // Give it a moment, then force kill if we own the process and it hangs.
        await Task.Delay(2000);
        if (_ownedProcess is { HasExited: false })
        {
            try { _ownedProcess.Kill(entireProcessTree: true); } catch { /* already gone */ }
        }
        _ownedProcess = null;
        onStatus?.Invoke("clamd stopped.");
    }
}
