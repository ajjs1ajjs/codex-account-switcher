using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace CodexAccountSwitcher;

public sealed record WindowsReleaseInfo(
    Version Version,
    Uri PageUri,
    Uri? DownloadUri,
    Uri? ChecksumUri,
    string? DigestSha256
);

public sealed class NativeSettings
{
    private const string Key = @"Software\CodexAccountSwitcher";
    private const string Run = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string WindowsAssetName = "Codex-Account-Switcher-windows-x64.exe";
    private const string WindowsChecksumAssetName = WindowsAssetName + ".sha256";
    private const long MaxInstallerBytes = 512L * 1024 * 1024;

    public string Version => typeof(NativeSettings).Assembly.GetName().Version!.ToString(3);
    public bool LaunchAtLogin {
        get { using var key = Registry.CurrentUser.OpenSubKey(Run); return key?.GetValue("CodexAccountSwitcher") is string; }
        set { using var key = Registry.CurrentUser.CreateSubKey(Run);
            if (value) key.SetValue("CodexAccountSwitcher", "\"" + Environment.ProcessPath + "\" --background");
            else key.DeleteValue("CodexAccountSwitcher", false); }
    }
    public bool AutomaticallyCheckUpdates {
        get { using var key = Registry.CurrentUser.OpenSubKey(Key); return key?.GetValue("AutomaticallyCheckUpdates") is not int number || number != 0; }
        set { using var key = Registry.CurrentUser.CreateSubKey(Key); key.SetValue("AutomaticallyCheckUpdates", value ? 1 : 0); }
    }
    public Version? AvailableVersion { get; private set; }
    public Uri? UpdatePage { get; private set; }
    public Uri? UpdateDownloadUri { get; private set; }
    public Uri? UpdateChecksumUri { get; private set; }
    public string? UpdateDigestSha256 { get; private set; }
    public bool IsChecking { get; private set; }
    public bool IsUpdating { get; private set; }
    public bool HasChecked { get; private set; }
    public string? UpdateError { get; private set; }
    public bool CanInstallInApp => UpdateDownloadUri != null && (UpdateDigestSha256 != null || UpdateChecksumUri != null);
    public Action? ShutdownForUpdate { get; set; }
    public event Action? Changed;

    public async Task CheckUpdatesAsync()
    {
        if (IsChecking || IsUpdating) return;
        IsChecking = true; UpdateError = null; Changed?.Invoke();
        try {
            using var http = CreateHttpClient(TimeSpan.FromSeconds(15));
            WindowsReleaseInfo? latest = null;
            for (var page = 1; ; page++) {
                using var document = JsonDocument.Parse(await http.GetStringAsync(
                    "https://api.github.com/repos/ajjs1ajjs/codex-account-switcher/releases?per_page=100&page=" + page));
                var candidate = LatestWindowsRelease(document.RootElement);
                if (candidate != null && (latest == null || candidate.Version > latest.Version)) latest = candidate;
                if (document.RootElement.GetArrayLength() < 100) break;
            }
            if (latest != null && latest.Version > new Version(Version)) {
                AvailableVersion = latest.Version;
                UpdatePage = latest.PageUri;
                UpdateDownloadUri = latest.DownloadUri;
                UpdateChecksumUri = latest.ChecksumUri;
                UpdateDigestSha256 = latest.DigestSha256;
            } else {
                AvailableVersion = null;
                UpdatePage = null;
                UpdateDownloadUri = null;
                UpdateChecksumUri = null;
                UpdateDigestSha256 = null;
            }
            HasChecked = true;
        } catch (Exception) { UpdateError = "update_check_failed"; }
        finally { IsChecking = false; Changed?.Invoke(); }
    }

    public async Task<bool> InstallUpdateAsync()
    {
        if (IsUpdating || IsChecking) return false;
        if (UpdateDownloadUri == null || !IsHttpsUri(UpdateDownloadUri) || (UpdateDigestSha256 == null && UpdateChecksumUri == null)) {
            UpdateError = "update_install_failed"; Changed?.Invoke(); return false;
        }
        var currentExe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(currentExe) || !currentExe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) {
            UpdateError = "update_install_failed"; Changed?.Invoke(); return false;
        }

        IsUpdating = true; UpdateError = null; Changed?.Invoke();
        var stagedPath = currentExe + ".new";
        var succeeded = false;
        try {
            using var http = CreateHttpClient(TimeSpan.FromMinutes(10));
            var expectedSha256 = UpdateDigestSha256;
            if (expectedSha256 == null && UpdateChecksumUri != null && IsHttpsUri(UpdateChecksumUri)) {
                var sumText = await http.GetStringAsync(UpdateChecksumUri);
                expectedSha256 = ParseSha256(sumText);
            }
            if (string.IsNullOrEmpty(expectedSha256)) throw new InvalidOperationException("Missing release SHA-256 digest.");

            await DownloadFileAsync(http, UpdateDownloadUri, stagedPath, MaxInstallerBytes);
            if (!VerifyFileSha256(stagedPath, expectedSha256)) {
                throw new InvalidOperationException("Downloaded update failed SHA-256 verification.");
            }

            ReplaceExecutable(currentExe, stagedPath);
            try {
                var start = new ProcessStartInfo(currentExe) { UseShellExecute = false };
                start.ArgumentList.Add("--wait-pid");
                start.ArgumentList.Add(Environment.ProcessId.ToString());
                if (Process.Start(start) == null) throw new InvalidOperationException("Could not start updated executable.");
            } catch {
                RestoreExecutable(currentExe);
                throw;
            }

            succeeded = true;
            ShutdownForUpdate?.Invoke();
            return true;
        } catch (Exception) {
            if (!succeeded) UpdateError = "update_install_failed";
            return false;
        } finally {
            TryDeleteFile(stagedPath);
            IsUpdating = false;
            Changed?.Invoke();
        }
    }

    // Stable unified releases must include a Windows executable.
    public static Version? LatestWindowsVersion(JsonElement releases) => LatestWindowsRelease(releases)?.Version;

    public static WindowsReleaseInfo? LatestWindowsRelease(JsonElement releases)
    {
        WindowsReleaseInfo? best = null;
        foreach (var release in releases.EnumerateArray()) {
            if (release.GetProperty("draft").GetBoolean()) continue;
            if (release.TryGetProperty("prerelease", out var preview) && preview.GetBoolean()) continue;
            var tag = release.GetProperty("tag_name").GetString();
            if (tag == null || !Regex.IsMatch(tag, @"\Av(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z")) continue;
            if (!System.Version.TryParse(tag[1..], out var version)) continue;

            Uri? downloadUri = null;
            Uri? checksumUri = null;
            string? digestSha256 = null;
            foreach (var asset in release.GetProperty("assets").EnumerateArray()) {
                var name = asset.GetProperty("name").GetString();
                if (name == WindowsAssetName) {
                    if (asset.TryGetProperty("browser_download_url", out var urlProp)
                        && Uri.TryCreate(urlProp.GetString(), UriKind.Absolute, out var parsed)
                        && IsHttpsUri(parsed)) {
                        downloadUri = parsed;
                    }
                    if (asset.TryGetProperty("digest", out var digestProp)) {
                        var raw = digestProp.GetString();
                        if (raw != null && raw.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) {
                            digestSha256 = ParseSha256(raw["sha256:".Length..]);
                        }
                    }
                } else if (name == WindowsChecksumAssetName) {
                    if (asset.TryGetProperty("browser_download_url", out var sumProp)
                        && Uri.TryCreate(sumProp.GetString(), UriKind.Absolute, out var parsed)
                        && IsHttpsUri(parsed)) {
                        checksumUri = parsed;
                    }
                }
            }
            if (downloadUri == null && !release.GetProperty("assets").EnumerateArray().Any(a => a.GetProperty("name").GetString() == WindowsAssetName)) {
                continue;
            }
            var pageUri = release.TryGetProperty("html_url", out var htmlProp)
                && Uri.TryCreate(htmlProp.GetString(), UriKind.Absolute, out var parsedPage)
                && IsHttpsUri(parsedPage)
                ? parsedPage
                : new Uri("https://github.com/ajjs1ajjs/codex-account-switcher/releases/tag/v" + version.ToString(3));

            if (best == null || version > best.Version) {
                best = new WindowsReleaseInfo(version, pageUri, downloadUri, checksumUri, digestSha256);
            }
        }
        return best;
    }

    public static string? ParseSha256(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var token = text.Trim().Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (token == null || !Regex.IsMatch(token, @"\A[0-9a-fA-F]{64}\z")) return null;
        return token.ToLowerInvariant();
    }

    public static bool VerifyFileSha256(string filePath, string expectedSha256)
    {
        var normalized = ParseSha256(expectedSha256);
        if (normalized == null || !File.Exists(filePath)) return false;
        using var stream = File.OpenRead(filePath);
        var actual = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        return string.Equals(actual, normalized, StringComparison.OrdinalIgnoreCase);
    }

    public static void ReplaceExecutable(string currentExePath, string stagedExePath)
    {
        var oldExePath = currentExePath + ".old";
        TryDeleteFile(oldExePath);
        File.Move(currentExePath, oldExePath);
        try {
            File.Move(stagedExePath, currentExePath);
        } catch {
            if (!File.Exists(currentExePath) && File.Exists(oldExePath)) {
                File.Move(oldExePath, currentExePath);
            }
            throw;
        }
    }

    public static void RestoreExecutable(string currentExePath)
    {
        var oldExePath = currentExePath + ".old";
        if (!File.Exists(oldExePath)) return;
        TryDeleteFile(currentExePath);
        if (!File.Exists(currentExePath)) {
            File.Move(oldExePath, currentExePath);
        }
    }

    public static void CleanupReplacedExecutable(string? processPath = null)
    {
        var target = processPath ?? Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(target)) return;
        foreach (var suffix in new[] { ".old", ".new" }) {
            var candidate = target + suffix;
            for (var attempt = 0; attempt < 20; attempt++) {
                if (!File.Exists(candidate)) break;
                try { File.Delete(candidate); break; }
                catch { Thread.Sleep(250); }
            }
        }
    }

    public void OpenUpdate() { if (UpdatePage != null) Process.Start(new ProcessStartInfo(UpdatePage.AbsoluteUri) { UseShellExecute = true })?.Dispose(); }

    private HttpClient CreateHttpClient(TimeSpan timeout)
    {
        var http = new HttpClient { Timeout = timeout };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("CodexAccountSwitcher/" + Version);
        return http;
    }

    private static bool IsHttpsUri(Uri uri) => string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static async Task DownloadFileAsync(HttpClient http, Uri uri, string destinationPath, long maxBytes)
    {
        using var response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is long len && len > maxBytes) {
            throw new InvalidOperationException("Update binary exceeds size limit.");
        }
        await using var source = await response.Content.ReadAsStreamAsync();
        await using var destination = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer)) > 0) {
            total += read;
            if (total > maxBytes) throw new InvalidOperationException("Update binary exceeds size limit.");
            await destination.WriteAsync(buffer.AsMemory(0, read));
        }
        await destination.FlushAsync();
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
