using System.Net.Http;
using System.Text.Json;

namespace ClamHub.Core;

/// <summary>
/// Reads the latest GitHub release of a repository (unauthenticated) so the app
/// can show the newest ClamHub and ClamAV versions with their release date and
/// offer a download. A private repo returns 404, which is reported as "no
/// release" rather than an error. Called from: UpdateCheckWindow.
/// </summary>
public static class GitHubReleaseClient
{
    /// <summary>A downloadable file attached to a release.</summary>
    public record ReleaseAsset(string Name, string DownloadUrl, long Size);

    /// <summary>Latest release: tag/name, publish date, web page and downloadable assets.</summary>
    public record ReleaseInfo(string Tag, string Name, DateTimeOffset? PublishedAt,
        string HtmlUrl, IReadOnlyList<ReleaseAsset> Assets);

    private static readonly HttpClient Http = CreateClient();

    /// <summary>
    /// Builds the shared client with the User-Agent header GitHub requires for
    /// API requests. Called from: static initialization.
    /// </summary>
    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("ClamHub");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return client;
    }

    /// <summary>
    /// Fetches the latest release for owner/repo. Returns null when the repo is
    /// private/unauthorized (404) or on any network/parse error, so callers show
    /// "not available" instead of failing. Called from: UpdateCheckWindow.
    /// </summary>
    public static async Task<ReleaseInfo?> GetLatestReleaseAsync(string owner, string repo,
        CancellationToken cancel = default)
    {
        try
        {
            var url = $"https://api.github.com/repos/{owner}/{repo}/releases/latest";
            using var resp = await Http.GetAsync(url, cancel);
            if (!resp.IsSuccessStatusCode) return null;

            var json = await resp.Content.ReadAsStringAsync(cancel);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string tag = GetString(root, "tag_name");
            string name = GetString(root, "name");
            string htmlUrl = GetString(root, "html_url");
            DateTimeOffset? published =
                root.TryGetProperty("published_at", out var p) && p.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(p.GetString(), out var dt)
                    ? dt
                    : null;

            var assets = new List<ReleaseAsset>();
            if (root.TryGetProperty("assets", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in arr.EnumerateArray())
                {
                    string an = GetString(a, "name");
                    string du = GetString(a, "browser_download_url");
                    long size = a.TryGetProperty("size", out var s) && s.TryGetInt64(out var sv) ? sv : 0;
                    if (an.Length > 0 && du.Length > 0)
                        assets.Add(new ReleaseAsset(an, du, size));
                }
            }

            return new ReleaseInfo(tag, name, published, htmlUrl, assets);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Reads a string property or "" when absent. Called from: GetLatestReleaseAsync.</summary>
    private static string GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : "";

    /// <summary>
    /// Picks the portable Windows x64 zip from a release's assets (name ends with
    /// .zip, mentions win and x64, and is not a debug build). Returns null when no
    /// asset matches. Called from: UpdateCheckWindow before downloading ClamAV.
    /// </summary>
    public static ReleaseAsset? FindWindowsX64Zip(IReadOnlyList<ReleaseAsset> assets)
        => assets.FirstOrDefault(a =>
        {
            var lower = a.Name.ToLowerInvariant();
            return lower.EndsWith(".zip")
                && lower.Contains("win")
                && (lower.Contains("x64") || lower.Contains("win64"))
                && !lower.Contains("debug");
        });
}
