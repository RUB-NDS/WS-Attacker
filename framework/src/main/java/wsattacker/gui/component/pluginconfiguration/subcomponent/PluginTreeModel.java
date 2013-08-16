/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.gui.component.pluginconfiguration.subcomponent;

import it.cnr.imaa.essi.lablib.gui.checkboxtree.CheckboxTree;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import org.apache.log4j.Logger;
import wsattacker.gui.composition.AbstractTreeModel;
import wsattacker.gui.util.PluginCategory;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginManagerListener;
import wsattacker.main.plugin.PluginManager;
import wsattacker.main.plugin.PluginState;
import wsattacker.util.Category;

public class PluginTreeModel extends AbstractTreeModel implements TreeModel, PluginManagerListener {

	private static final Logger LOG = Logger.getLogger(PluginTreeCellRenderer.class);
	public static final String PROP_TREE = "tree";
	public static final String PROP_PLUGINMANAGER = "pluginManager";
	Category<String, AbstractPlugin> rootCategory;
	Category<String, AbstractPlugin> allCategory;
	Category<String, AbstractPlugin> activeCategory;
	Category<String, AbstractPlugin> abcCategory;
	private CheckboxTree tree = new CheckboxTree();
	private transient final PropertyChangeSupport propertyChangeSupport = new PropertyChangeSupport(this);
	private PluginManager pluginManager;

	public PluginTreeModel() {
		rootCategory = new PluginCategory("root");
		allCategory = new PluginCategory("All Plugins");
		activeCategory = new PluginCategory("Active Plugins");
		abcCategory = new PluginCategory("Alphabetical Sorted");
		allCategory = rootCategory.addCategory(allCategory);
		activeCategory = rootCategory.addCategory(activeCategory);
		abcCategory = rootCategory.addCategory(abcCategory);
		setPluginManager(PluginManager.getInstance());
	}

	/**
	 * Get the value of tree
	 *
	 * @return the value of tree
	 */
	public CheckboxTree getTree() {
		return tree;
	}

	/**
	 * Set the value of tree
	 *
	 * @param tree new value of tree
	 */
	public void setTree(CheckboxTree tree) {
		CheckboxTree oldTree = this.tree;
		this.tree = tree;
		propertyChangeSupport.firePropertyChange(PROP_TREE, oldTree, tree);
	}

	/**
	 * Add PropertyChangeListener.
	 *
	 * @param listener
	 */
	public void addPropertyChangeListener(PropertyChangeListener listener) {
		propertyChangeSupport.addPropertyChangeListener(listener);
	}

	/**
	 * Remove PropertyChangeListener.
	 *
	 * @param listener
	 */
	public void removePropertyChangeListener(PropertyChangeListener listener) {
		propertyChangeSupport.removePropertyChangeListener(listener);
	}

	/**
	 * Get the value of pluginManager
	 *
	 * @return the value of pluginManager
	 */
	public PluginManager getPluginManager() {
		return pluginManager;
	}

	/**
	 * Set the value of pluginManager
	 *
	 * @param pluginManager new value of pluginManager
	 */
	public void setPluginManager(PluginManager pluginManager) {
		PluginManager oldPluginManager = this.pluginManager;
		this.pluginManager = pluginManager;
		propertyChangeSupport.firePropertyChange(PROP_PLUGINMANAGER, oldPluginManager, pluginManager);
		if (oldPluginManager != null) {
			oldPluginManager.removeListener(this);
		}
		if (pluginManager != null) {
			pluginManager.addListener(this);
		}
		pluginContainerChanged();
	}

	@Override
	public Object getChild(Object parent, int index) {
		if (parent.getClass().isAssignableFrom(rootCategory.getClass())) {
			return ((Category<String, AbstractPlugin>) parent).getNode(index);
		}
		return null;
	}

	@Override
	public int getChildCount(Object node) {
		int count = 0;
		if (node.getClass().isAssignableFrom(rootCategory.getClass())) {
			count = ((Category<String, AbstractPlugin>) node).countNodes();
		}
		return count;
	}

	@Override
	public int getIndexOfChild(Object parent, Object node) {
		int result = 0;
		if (parent.getClass().isAssignableFrom(rootCategory.getClass())) {
			result = ((Category<String, AbstractPlugin>) parent).getIndexOfNode(node);
		}
		return result;
	}

	@Override
	public Object getRoot() {
		return rootCategory;
	}

	@Override
	public boolean isLeaf(Object maybeLeaf) {
		return (maybeLeaf instanceof AbstractPlugin);
	}

	@Override
	public void valueForPathChanged(TreePath path, Object newValue) {
		LOG.warn("### WARNING ###");
	}

	@Override
	public void currentPointsChanged(AbstractPlugin plugin, int newPoints) {
	}

	@Override
	public void pluginStateChanged(AbstractPlugin plugin, PluginState newState, PluginState oldState) {
		tree.repaint();
	}

	@Override
	public synchronized void pluginActiveStateChanged(AbstractPlugin plugin, boolean active) {
		LOG.debug("### Checked Pre:");
		for (TreePath x : tree.getCheckingPaths()) {
			LOG.debug("    " + x);
		}
		Category<String, AbstractPlugin> zwerg = allCategory;
		TreePath allPath = new TreePath(new Object[]{rootCategory, allCategory});
		for (String key : plugin.getCategory()) {
			zwerg = zwerg.getSubCategory(key);
			if (zwerg == null) {
				LOG.error("Error finding path");
				return;
			}
			allPath = allPath.pathByAddingChild(zwerg);
		}
		allPath = allPath.pathByAddingChild(plugin);
		TreePath activePath = new TreePath(new Object[]{rootCategory, activeCategory, plugin});
		TreePath abcPath = new TreePath(new Object[]{rootCategory, abcCategory, plugin});
		if (active) {
			if (activeCategory.addLeaf(plugin)) {
				fireChildAdded(activePath.getParentPath(), activeCategory.getIndexOfNode(plugin), plugin);
				tree.addCheckingPath(allPath);
				tree.addCheckingPath(activePath.getParentPath());
				tree.addCheckingPath(abcPath);
			}
		} else {
			int index = activeCategory.getIndexOfNode(plugin);
			if (activeCategory.removeLeaf(plugin)) {
				tree.removeCheckingPath(allPath);
				tree.removeCheckingPath(activePath);
				tree.removeCheckingPath(abcPath);
				fireChildRemoved(activePath.getParentPath(), index, plugin);
			}
		}
		LOG.debug("### Checked After:");
		for (TreePath x : tree.getCheckingPaths()) {
			LOG.debug(String.format("    %s %s", x, x.getLastPathComponent().getClass()));
		}
		//			rootCategory.print();
		//			tree.repaint();
		//			tree.updateUI();
		for (int i = 0; i < tree.getRowCount(); ++i) {
			TreePath x = tree.getPathForRow(i);
			boolean checked = tree.getCheckingModel().isPathChecked(x);
			boolean enabled = tree.getCheckingModel().isPathEnabled(x);
			boolean greyed = tree.getCheckingModel().isPathGreyed(x);
			LOG.debug(x + (checked ? " (Checked)" : "") + (enabled ? " (Enabled)" : "") + (greyed ? " (Greyed)" : ""));
		}
	}

	@Override
	public synchronized void pluginContainerChanged() {
		allCategory.removeAllNodes(true);
		abcCategory.removeAllNodes(true);
		activeCategory.removeAllNodes(true);
		for (AbstractPlugin plugin : pluginManager) {
			allCategory.createPath(plugin.getCategory()).addLeaf(plugin);
			abcCategory.addLeaf(plugin);
		}
		fireNewRoot();
	}
}
