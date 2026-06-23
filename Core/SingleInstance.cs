using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace ClamHub.Core;

/// <summary>
/// Single-instance coordination. The first ClamHub process owns a named mutex
/// and runs a named-pipe server; further launches (e.g. the context menu entry)
/// detect the running instance, forward their scan path to it and exit, so no
/// second window opens. Falls back to starting normally if no instance is found.
/// Called from: App.OnStartup (detection) and MainWindow (server).
/// </summary>
public static class SingleInstance
{
    private const string MutexName = @"Local\ClamHub.SingleInstance";
    private const string PipeName = "ClamHub.Scan";

    /// <summary>Message sent when a launch has no scan path (just focus the app).</summary>
    public const string ActivateMessage = "__ACTIVATE__";

    private static Mutex? _mutex;

    /// <summary>
    /// True if this process is the first instance (and now owns the mutex).
    /// Keep the returned state for the process lifetime. Called from: App.OnStartup.
    /// </summary>
    public static bool ClaimPrimary()
    {
        _mutex = new Mutex(true, MutexName, out bool createdNew);
        return createdNew;
    }

    /// <summary>
    /// Releases the single-instance mutex so a copy relaunched moments later (a
    /// restart) can claim primary instead of seeing this still-exiting process and
    /// quitting itself. Called from: MainWindow restart handlers before relaunch.
    /// </summary>
    public static void ReleasePrimary()
    {
        try { _mutex?.Dispose(); }
        catch { /* nothing useful to do if it is already gone */ }
        _mutex = null;
    }

    /// <summary>
    /// Sends a message (a path or ActivateMessage) to the running instance.
    /// Best effort with a short timeout. Called from: App.OnStartup when not primary.
    /// </summary>
    public static void SendToPrimary(string message)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
            client.Connect(2000);
            using var writer = new StreamWriter(client) { AutoFlush = true };
            writer.WriteLine(message);
        }
        catch
        {
            // If the primary cannot be reached, the launch simply does nothing.
        }
    }

    /// <summary>
    /// Starts the background pipe server. Each received line is handed to
    /// onMessage (the caller marshals to the UI thread). Called from: MainWindow.
    /// </summary>
    public static void StartServer(Action<string> onMessage)
    {
        Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1);
                    await server.WaitForConnectionAsync();
                    using var reader = new StreamReader(server);
                    string? line = await reader.ReadLineAsync();
                    if (!string.IsNullOrEmpty(line)) onMessage(line);
                }
                catch
                {
                    // Ignore a single failed connection and keep listening.
                }
            }
        });
    }
}
