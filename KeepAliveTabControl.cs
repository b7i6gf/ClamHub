using System.Windows;
using System.Windows.Controls;

namespace ClamHub;

/// <summary>
/// A TabControl that keeps every tab's content in the visual tree once it has been
/// shown, instead of discarding and rebuilding it on each switch (the default
/// TabControl behavior). The selected tab's content stays visible; the others are
/// collapsed. This removes the per-switch visual-tree rebuild that makes switching
/// to control-heavy tabs (Scan, Settings) stutter, especially on weak hardware.
///
/// The matching control template (in App.xaml) replaces the single selected-content
/// host with a "PART_ItemsHolder" panel that this control fills with one content
/// host per tab. The tab headers are still rendered by the header-only TabItem
/// template, so each tab's body has exactly one visual parent (its host here).
/// Used by: MainWindow.xaml (the main tab strip "MainTabs").
/// </summary>
public class KeepAliveTabControl : TabControl
{
    private Panel? _itemsHolder;

    /// <summary>Grabs PART_ItemsHolder from the applied template. Called by: WPF on template apply.</summary>
    public override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
        _itemsHolder = GetTemplateChild("PART_ItemsHolder") as Panel;
        RefreshHeldContent();
    }

    /// <summary>Updates which held content is visible. Called by: WPF when the selected tab changes.</summary>
    protected override void OnSelectionChanged(SelectionChangedEventArgs e)
    {
        base.OnSelectionChanged(e);
        RefreshHeldContent();
    }

    /// <summary>Rebuilds the hosts when tabs are added or removed (and on initial
    /// population, in case items arrive after the template). Called by: WPF.</summary>
    protected override void OnItemsChanged(System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
    {
        base.OnItemsChanged(e);
        RefreshHeldContent();
    }

    /// <summary>
    /// Ensures every tab has a content host (created once) and shows only the
    /// selected tab's host. Called from: OnApplyTemplate and OnSelectionChanged.
    /// </summary>
    private void RefreshHeldContent()
    {
        if (_itemsHolder == null) return;

        // Create a host for any tab that does not have one yet (content built once).
        foreach (var item in Items)
        {
            if (FindHost(item) == null)
            {
                _itemsHolder.Children.Add(new ContentPresenter
                {
                    Content = (item as TabItem)?.Content ?? item,
                    Tag = item,
                    Visibility = Visibility.Collapsed
                });
            }
        }

        // Remove hosts whose tab no longer exists (keeps the holder in sync).
        for (int i = _itemsHolder.Children.Count - 1; i >= 0; i--)
        {
            if (_itemsHolder.Children[i] is ContentPresenter cp && !Items.Contains(cp.Tag))
                _itemsHolder.Children.RemoveAt(i);
        }

        // Only the selected tab's content is visible; the rest stay collapsed but loaded.
        foreach (var child in _itemsHolder.Children)
        {
            if (child is ContentPresenter cp)
                cp.Visibility = ReferenceEquals(cp.Tag, SelectedItem)
                    ? Visibility.Visible
                    : Visibility.Collapsed;
        }
    }

    /// <summary>Returns the content host created for the given tab, or null. Called from: RefreshHeldContent.</summary>
    private ContentPresenter? FindHost(object item)
    {
        if (_itemsHolder == null) return null;
        foreach (var child in _itemsHolder.Children)
            if (child is ContentPresenter cp && ReferenceEquals(cp.Tag, item))
                return cp;
        return null;
    }
}
