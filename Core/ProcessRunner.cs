using System.Diagnostics;
using System.IO;

namespace ClamAVGui.Core;

/// <summary>
/// Runs external ClamAV executables asynchronously and streams stdout/stderr
/// line by line to a callback, so the UI can show live output.
/// Called from: UpdateManager, DaemonController and later ScanEngine (stage 3).
/// </summary>
public static class ProcessRunner
{
    /// <summary>Result of a finished process run.</summary>
    public record RunResult(int ExitCode, bool Started, string? StartError);

    /// <summary>
    /// Starts an executable with arguments and awaits its completion.
    /// onOutput is invoked for every stdout and stderr line (UI thread marshalling
    /// is the caller's responsibility). Returns exit code or start error.
    /// Called from: UpdateManager.RunUpdateAsync, ScanEngine (stage 3).
    /// </summary>
    public static async Task<RunResult> RunAsync(
        string exePath,
        string arguments,
        Action<string>? onOutput,
        CancellationToken cancel = default)
    {
        if (!File.Exists(exePath))
            return new RunResult(-1, false, $"Executable not found: {exePath}");

        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = arguments,
            WorkingDirectory = AppPaths.ClamAvDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };

        process.OutputDataReceived += (_, e) => { if (e.Data != null) onOutput?.Invoke(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data != null) onOutput?.Invoke(e.Data); };

        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            return new RunResult(-1, false, ex.Message);
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        try
        {
            await process.WaitForExitAsync(cancel);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
            throw;
        }

        return new RunResult(process.ExitCode, true, null);
    }

    /// <summary>
    /// Fire and forget start for long running background processes (clamd).
    /// Returns the Process handle or null when the start failed.
    /// Called from: DaemonController.StartAsync.
    /// </summary>
    public static Process? StartDetached(string exePath, string arguments, out string? error)
    {
        error = null;
        if (!File.Exists(exePath))
        {
            error = $"Executable not found: {exePath}";
            return null;
        }

        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = arguments,
            WorkingDirectory = AppPaths.ClamAvDir,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            return Process.Start(psi);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
    }
}
