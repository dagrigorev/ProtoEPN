using System.IO;
using System.Text.Json;

namespace Epn.WindowsGui.Services;

public static class UserSettings
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "EPN",
        "windows-gui.json");

    public static string Get(string key, string fallback)
    {
        try
        {
            var data = Load();
            return data.TryGetValue(key, out var value) ? value : fallback;
        }
        catch
        {
            return fallback;
        }
    }

    public static void Set(string key, string value)
    {
        var data = Load();
        data[key] = value;
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
        File.WriteAllText(SettingsPath, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static Dictionary<string, string> Load()
    {
        if (!File.Exists(SettingsPath))
        {
            return new Dictionary<string, string>();
        }

        return JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(SettingsPath))
            ?? new Dictionary<string, string>();
    }
}
