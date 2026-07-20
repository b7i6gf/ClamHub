using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace ClamHub.Core;

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
            // WaitForExitAsync does NOT guarantee the async output pipes are drained;
            // the parameterless WaitForExit() does. Without this a scan's last lines
            // (final FOUND entries, the summary) could sporadically be lost. The
            // process has already exited here, so this returns immediately after
            // flushing the remaining OutputDataReceived/ErrorDataReceived events.
            process.WaitForExit();
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
            throw;
        }

        return new RunResult(process.ExitCode, true, null);
    }

    /// <summary>
    /// Like RunAsync, but also writes text to the process's standard input and then
    /// closes it so the child sees end-of-input. Needed by tools that read their work
    /// from stdin (sigtool --decode-sigs). Output is still streamed line by line via
    /// onOutput, so a child that prints while we write cannot deadlock.
    /// Called from: SigTool.DecodeSignatureAsync.
    /// </summary>
    public static async Task<RunResult> RunWithInputAsync(
        string exePath,
        string arguments,
        string stdinText,
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
            RedirectStandardInput = true,
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
            await process.StandardInput.WriteLineAsync(stdinText);
            await process.StandardInput.FlushAsync();
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // The child exited before reading its input; its exit code still applies.
        }
        finally
        {
            try { process.StandardInput.Close(); } catch { /* already closed */ }
        }

        try
        {
            await process.WaitForExitAsync(cancel);
            // Drain the async output pipes (see the note in RunAsync).
            process.WaitForExit();
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
    /// <summary>
    /// Starts a long-running background process that must SURVIVE the lifetime of
    /// this ClamHub process and of any sibling launch (clamd). The plain
    /// Process.Start with UseShellExecute=false creates a normal CHILD, which
    /// stays inside the parent's job object: when Explorer or the shell puts a
    /// launch into a job with kill-on-close, the daemon dies with it, which is
    /// exactly the "clamd stops after every context menu action" symptom.
    ///
    /// CreateProcess is therefore called directly with
    /// CREATE_BREAKAWAY_FROM_JOB (leave the caller's job entirely),
    /// DETACHED_PROCESS + CREATE_NO_WINDOW (no console attachment) and
    /// CREATE_NEW_PROCESS_GROUP (no inherited Ctrl+C/Ctrl+Break). If the job
    /// forbids breakaway (ERROR_ACCESS_DENIED), it retries without that flag so
    /// the daemon still starts.
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

        // CreateProcess may modify the command line buffer, so it must be writable.
        string commandLine = $"\"{exePath}\" {arguments}";

        var process = TryCreateProcess(exePath, commandLine,
            CreateBreakawayFromJob | DetachedProcess | CreateNoWindow | CreateNewProcessGroup,
            out error);
        if (process != null) return process;

        // Breakaway is not permitted inside this job: start without it rather than
        // not at all (the daemon then behaves as before this hardening).
        process = TryCreateProcess(exePath, commandLine,
            DetachedProcess | CreateNoWindow | CreateNewProcessGroup, out var fallbackError);
        if (process != null) { error = null; return process; }

        error ??= fallbackError;
        return null;
    }

    private const uint DetachedProcess = 0x00000008;
    private const uint CreateNewProcessGroup = 0x00000200;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateBreakawayFromJob = 0x01000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public uint cb;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string? lpApplicationName, System.Text.StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref StartupInfo lpStartupInfo, out ProcessInformation lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// One CreateProcess attempt with the given creation flags. Returns the
    /// Process wrapper for the new pid, or null with the Win32 message in error.
    /// Called from: StartDetached (normal attempt and breakaway fallback).
    /// </summary>
    private static Process? TryCreateProcess(string exePath, string commandLine,
        uint flags, out string? error)
    {
        error = null;
        var si = new StartupInfo();
        si.cb = (uint)Marshal.SizeOf<StartupInfo>();
        var cmd = new System.Text.StringBuilder(commandLine);

        if (!CreateProcessW(exePath, cmd, IntPtr.Zero, IntPtr.Zero, false,
                flags, IntPtr.Zero, AppPaths.ClamAvDir, ref si, out var pi))
        {
            error = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message;
            return null;
        }

        // The handles are not needed: the process is intentionally independent.
        try { CloseHandle(pi.hThread); } catch { /* best effort */ }
        try { CloseHandle(pi.hProcess); } catch { /* best effort */ }

        try
        {
            return Process.GetProcessById((int)pi.dwProcessId);
        }
        catch
        {
            // It started but exited immediately, or we cannot open it; the caller's
            // readiness poll decides what that means.
            return null;
        }
    }
}
