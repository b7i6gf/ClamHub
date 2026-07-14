using System;
using System.Windows.Controls;

namespace ClamHub;

/// <summary>
/// Shared column sorting for every GridView table (History, Quarantine, Signatures,
/// Detections): 3-state cycle ascending -> descending -> unsorted with an arrow on
/// the active header. Extracted from MainWindow.History.cs (v1.0.3.2) so windows
/// outside MainWindow can use it too. Headers must be a TextBlock whose Tag is the
/// row property name. Called from: the *Sort_Click handlers.
/// </summary>
public static class ListViewSorting
{
    /// <summary>
    /// Sorts a ListView by the property in the clicked header's Tag. Repeated clicks on the
    /// SAME column cycle through three states: ascending, then descending, then UNSORTED
    /// (the source/default order is restored and the arrow cleared). Clicking a different
    /// column starts ascending. Uses a CustomSort comparer (ColumnComparer) so numeric and
    /// date columns sort by value, not lexicographically. Shared by all three tables.
    /// Called from: the *Sort_Click wrappers in MainWindow and DetectionsWindow.
    /// </summary>
    public static void SortByColumn(GridViewColumnHeader? header, ListView list)
    {
        // Ignore clicks on the padding header or the resize gripper.
        if (header?.Column?.Header is not TextBlock tb || tb.Tag is not string prop
            || string.IsNullOrEmpty(prop))
            return;

        // ListCollectionView is what GetDefaultView returns for a List<T> and it is the
        // only view type that supports CustomSort.
        if (System.Windows.Data.CollectionViewSource.GetDefaultView(list.ItemsSource)
                is not System.Windows.Data.ListCollectionView view)
            return;

        if (view.CustomSort is ColumnComparer cur && cur.Property == prop)
        {
            if (!cur.Descending)
            {
                // 2nd click: ascending -> descending.
                view.CustomSort = new ColumnComparer(prop, true);
                UpdateSortArrows(list, prop, System.ComponentModel.ListSortDirection.Descending);
            }
            else
            {
                // 3rd click: descending -> unsorted. Clearing CustomSort makes the view
                // fall back to the underlying list order (the tab's default).
                view.CustomSort = null;
                UpdateSortArrows(list, null, System.ComponentModel.ListSortDirection.Ascending);
            }
            return;
        }

        // 1st click (or a different column): ascending.
        view.CustomSort = new ColumnComparer(prop, false);
        UpdateSortArrows(list, prop, System.ComponentModel.ListSortDirection.Ascending);
    }

    /// <summary>
    /// Value-aware comparer used as a ListCollectionView.CustomSort for the data tables.
    /// Reads the named property from each row (via reflection, cached per row type since a
    /// table holds one type) and compares smartly: DateTime chronologically; two values
    /// that both parse as numbers by numeric value; a number before plain text; otherwise
    /// a culture-aware case-insensitive string compare. This fixes numeric string columns
    /// like the Signatures count sorting lexicographically. Used by: SortByColumn.
    /// </summary>
    private sealed class ColumnComparer : System.Collections.IComparer
    {
        public string Property { get; }
        public bool Descending { get; }

        private System.Reflection.PropertyInfo? _pi;
        private Type? _piType;

        public ColumnComparer(string property, bool descending)
        {
            Property = property;
            Descending = descending;
        }

        /// <summary>Reflects the sort property off a row, caching the PropertyInfo for the
        /// row type (all rows in one table share a type). Called from: Compare.</summary>
        private object? Value(object? row)
        {
            if (row == null) return null;
            var t = row.GetType();
            if (_pi == null || _piType != t) { _piType = t; _pi = t.GetProperty(Property); }
            return _pi?.GetValue(row);
        }

        /// <summary>Compares two rows by the sort property, applying the direction. Called from: the view.</summary>
        public int Compare(object? x, object? y)
        {
            int cmp = CompareValues(Value(x), Value(y));
            return Descending ? -cmp : cmp;
        }

        /// <summary>Type-aware value compare (DateTime, numeric, date-like strings, then
        /// text). Called from: Compare.</summary>
        private static int CompareValues(object? a, object? b)
        {
            if (a == null && b == null) return 0;
            if (a == null) return -1;
            if (b == null) return 1;
            if (a is DateTime da && b is DateTime db) return DateTime.Compare(da, db);

            string sa = a.ToString() ?? "";
            string sb = b.ToString() ?? "";
            var inv = System.Globalization.CultureInfo.InvariantCulture;
            var style = System.Globalization.NumberStyles.Number;
            bool na = double.TryParse(sa, style, inv, out double va);
            bool nb = double.TryParse(sb, style, inv, out double vb);
            if (na && nb) return va.CompareTo(vb);
            if (na != nb) return na ? -1 : 1; // numbers sort before non-numeric text

            // The Built column mixes formats ("11 Sep 2025 08:29 -0400" from sigtool vs
            // "2026-07-10 19:01" file dates); plain text compare would order those
            // wrongly, so date-like strings are compared chronologically. Pure numbers
            // never reach this branch (handled above), so "339" cannot be misread.
            bool ta = DateTime.TryParse(sa, inv, System.Globalization.DateTimeStyles.None, out var dta)
                   || DateTime.TryParse(sa, out dta);
            bool tb = DateTime.TryParse(sb, inv, System.Globalization.DateTimeStyles.None, out var dtb)
                   || DateTime.TryParse(sb, out dtb);
            if (ta && tb) return DateTime.Compare(dta, dtb);
            if (ta != tb) return ta ? -1 : 1; // dates sort before plain text ("n/a", "-")

            return string.Compare(sa, sb, StringComparison.CurrentCultureIgnoreCase);
        }
    }

    /// <summary>
    /// Sets an up/down arrow on the active column header and clears it from the others.
    /// A null prop (unsorted) clears every arrow. Called from: SortByColumn.
    /// </summary>
    private static void UpdateSortArrows(ListView list, string? prop,
        System.ComponentModel.ListSortDirection dir)
    {
        if (list.View is not GridView grid) return;
        foreach (var col in grid.Columns)
        {
            if (col.Header is not TextBlock t) continue;
            string baseTitle = t.Text.Replace(" \u25B2", "").Replace(" \u25BC", "");
            bool active = (t.Tag as string) == prop;
            t.Text = active
                ? baseTitle + (dir == System.ComponentModel.ListSortDirection.Ascending ? " \u25B2" : " \u25BC")
                : baseTitle;
        }
    }
}
