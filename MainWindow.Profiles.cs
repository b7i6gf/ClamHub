using System.Windows;
using System.Windows.Controls;
using ClamHub.Core;
using ClamHub.Models;

namespace ClamHub;

/// <summary>
/// Scan profile handling: fills the profile combo, applies a selected profile
/// to the scan fields and saves/deletes profiles. Partial class companion to
/// MainWindow.xaml.cs, initialized from InitializeAsync.
/// </summary>
public partial class MainWindow
{
    /// <summary>Suppresses SelectionChanged side effects while the combo is rebuilt.</summary>
    private bool _profileComboUpdating;

    /// <summary>
    /// Loads profiles.json and fills the combo box.
    /// Called from: MainWindow.InitializeAsync.
    /// </summary>
    private void InitializeProfiles()
    {
        ProfileManager.Load();
        RefreshProfileCombo(null);
    }

    /// <summary>
    /// Rebuilds the combo items and optionally selects a profile by name.
    /// Called from: InitializeProfiles, SaveProfile_Click, DeleteProfile_Click.
    /// </summary>
    private void RefreshProfileCombo(string? selectName)
    {
        _profileComboUpdating = true;
        ProfileCombo.Items.Clear();
        foreach (var profile in ProfileManager.Profiles)
            ProfileCombo.Items.Add(profile.Name);
        _profileComboUpdating = false;

        if (selectName != null)
            ProfileCombo.SelectedItem = selectName;
    }

    /// <summary>
    /// Applies the selected profile to the scan fields.
    /// Called from: XAML SelectionChanged binding of ProfileCombo.
    /// </summary>
    private void ProfileCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_profileComboUpdating || ProfileCombo.SelectedItem is not string name) return;
        var profile = ProfileManager.Profiles.FirstOrDefault(p => p.Name == name);
        if (profile == null) return;

        TargetBox.Text = profile.TargetPath;
        ActionCombo.SelectedIndex = (int)profile.Action;
        ExtensionsBox.Text = profile.Extensions;
        // Profiles do not carry their own exclusions; switching profile returns
        // the scan-session exclusions to the persistent settings defaults.
        ResetSessionExclusions();
        AppendLine($"Profile applied: {profile.Name}");
    }

    /// <summary>
    /// Saves the current scan fields as a profile. Name source: the name box,
    /// or the selected profile when the box is empty (overwrite).
    /// Called from: XAML Click binding (profile Save).
    /// </summary>
    private void SaveProfile_Click(object sender, RoutedEventArgs e)
    {
        var name = ProfileNameBox.Text.Trim();
        if (name.Length == 0)
            name = ProfileCombo.SelectedItem as string ?? "";
        if (name.Length == 0)
        {
            AppendLine("Profile: enter a name (or select a profile to overwrite) before saving.");
            return;
        }

        ProfileManager.AddOrUpdate(new ScanProfile
        {
            Name = name,
            TargetPath = TargetBox.Text.Trim(),
            Action = (InfectedFileAction)ActionCombo.SelectedIndex,
            Extensions = ExtensionsBox.Text.Trim()
        });

        ProfileNameBox.Text = "";
        RefreshProfileCombo(name);
        AppendLine($"Profile saved: {name}");
    }

    /// <summary>
    /// Deletes the selected profile after confirmation.
    /// Called from: XAML Click binding (profile Delete).
    /// </summary>
    private void DeleteProfile_Click(object sender, RoutedEventArgs e)
    {
        if (ProfileCombo.SelectedItem is not string name)
        {
            AppendLine("Profile: select a profile to delete.");
            return;
        }

        if (!Confirm("Delete profile", $"Delete profile \"{name}\"?", "Delete", "Cancel"))
            return;

        ProfileManager.Delete(name);
        RefreshProfileCombo(null);
        AppendLine($"Profile deleted: {name}");
    }
}
