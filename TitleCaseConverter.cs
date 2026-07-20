using System.Globalization;
using System.Windows.Data;

namespace ClamHub;

/// <summary>
/// Display-only converter that capitalizes the first letter of every word and
/// leaves the rest of each word untouched: "Integrity check" -> "Integrity
/// Check", "1 infected (quarantined)" -> "1 Infected (Quarantined)"; acronyms
/// and mixed-case names ("VT", "PE", "ClamAV") stay intact, numbers and version
/// strings are unaffected. Used by the History list's Kind and Result columns,
/// so entries already stored in history.json render capitalized too, WITHOUT
/// rewriting stored data or the exported report texts. Registered in App.xaml
/// resources under the key "TitleCase".
/// </summary>
public sealed class TitleCaseConverter : IValueConverter
{
    /// <summary>Capitalizes word starts for display. A "word start" is the first
    /// letter after whitespace or leading punctuation such as "(". Called from:
    /// the History column bindings in MainWindow.xaml.</summary>
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string s || s.Length == 0) return value;
        var chars = s.ToCharArray();
        bool atWordStart = true;
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (char.IsWhiteSpace(c)) { atWordStart = true; continue; }
            if (atWordStart && char.IsLetter(c))
            {
                chars[i] = char.ToUpper(c, culture);
                atWordStart = false;
            }
            else if (char.IsLetterOrDigit(c))
            {
                // Inside a word (or after a digit like "1"): keep casing as-is.
                atWordStart = false;
            }
            // Punctuation such as "(" or "-" keeps atWordStart true, so the
            // letter following it still counts as a word start.
        }
        return new string(chars);
    }

    /// <summary>One-way display converter; never converted back.</summary>
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
