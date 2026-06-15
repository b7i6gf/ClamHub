using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace ClamAVGui.Core;

/// <summary>
/// Looks up file hashes on VirusTotal (API v3). Privacy by design: only the
/// locally computed SHA256 is sent, the file itself is never uploaded. The API
/// key comes from settings.json (AppSettings.VirusTotalApiKey) and is sent as
/// a request header, it is never written to logs or console output.
/// Free tier limits (4 requests/min) are respected by a built-in throttle.
/// Called from: MainWindow VirusTotal button on the hash tab.
/// </summary>
public static class VirusTotalClient
{
    /// <summary>Result of one hash lookup.</summary>
    public record VtResult(
        bool Success,
        bool NotFound,
        string? Error,
        int Malicious,
        int Suspicious,
        int Harmless,
        int Undetected);

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <summary>Minimum spacing between requests (free tier: 4 per minute).</summary>
    private static readonly TimeSpan MinRequestGap = TimeSpan.FromSeconds(15);
    private static DateTime _lastRequest = DateTime.MinValue;

    /// <summary>
    /// Queries VirusTotal for a SHA256 hash and returns the engine verdict
    /// statistics. Waits automatically when the rate limit gap is not yet over.
    /// Called from: MainWindow.VirusTotal_Click.
    /// </summary>
    public static async Task<VtResult> LookupAsync(string sha256, string apiKey,
        Action<string>? onStatus = null, CancellationToken cancel = default)
    {
        // Local throttle for the free tier rate limit.
        var wait = _lastRequest + MinRequestGap - DateTime.UtcNow;
        if (wait > TimeSpan.Zero)
        {
            onStatus?.Invoke($"Rate limit: waiting {wait.TotalSeconds:0}s before the request...");
            await Task.Delay(wait, cancel);
        }
        _lastRequest = DateTime.UtcNow;

        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://www.virustotal.com/api/v3/files/{sha256.ToLowerInvariant()}");
        request.Headers.Add("x-apikey", apiKey);

        HttpResponseMessage response;
        try
        {
            response = await Http.SendAsync(request, cancel);
        }
        catch (HttpRequestException ex)
        {
            return Fail($"Network error: {ex.Message}");
        }
        catch (TaskCanceledException) when (!cancel.IsCancellationRequested)
        {
            return Fail("Request timed out.");
        }

        using (response)
        {
            switch (response.StatusCode)
            {
                case HttpStatusCode.NotFound:
                    return new VtResult(true, true, null, 0, 0, 0, 0);
                case HttpStatusCode.Unauthorized:
                    return Fail("API key rejected (401). Check VirusTotalApiKey in settings.json.");
                case (HttpStatusCode)429:
                    return Fail("VirusTotal rate limit reached (429). Try again later.");
            }
            if (!response.IsSuccessStatusCode)
                return Fail($"VirusTotal returned HTTP {(int)response.StatusCode}.");

            try
            {
                var json = await response.Content.ReadAsStringAsync(cancel);
                using var doc = JsonDocument.Parse(json);
                var stats = doc.RootElement
                    .GetProperty("data")
                    .GetProperty("attributes")
                    .GetProperty("last_analysis_stats");

                int Get(string name) =>
                    stats.TryGetProperty(name, out var v) ? v.GetInt32() : 0;

                return new VtResult(true, false, null,
                    Get("malicious"), Get("suspicious"), Get("harmless"), Get("undetected"));
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                return Fail("Unexpected response format from VirusTotal.");
            }
        }

        static VtResult Fail(string message) => new(false, false, message, 0, 0, 0, 0);
    }
}
