/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010  Christian Mainka
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package wsattacker.gui.component.plugin.subcomponent;

import it.cnr.imaa.essi.lablib.gui.checkboxtree.CheckboxTree;
import it.cnr.imaa.essi.lablib.gui.checkboxtree.DefaultCheckboxTreeCellRenderer;
import it.cnr.imaa.essi.lablib.gui.checkboxtree.TreeCheckingEvent;
import it.cnr.imaa.essi.lablib.gui.checkboxtree.TreeCheckingListener;
import it.cnr.imaa.essi.lablib.gui.checkboxtree.TreeCheckingModel;

import java.awt.Component;
import java.awt.FlowLayout;
import java.util.Iterator;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import wsattacker.gui.composition.AbstractTreeModel;
import wsattacker.gui.util.PluginCategory;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginManagerListener;
import wsattacker.main.plugin.PluginManager;
import wsattacker.main.plugin.PluginState;
import wsattacker.util.Category;

public class PluginTree extends CheckboxTree {
	private static final long serialVersionUID = 1L;
	ControllerInterface controller;
	PluginManager manager;
	PluginTreeModel model;

	public PluginTree(ControllerInterface c) {
		super();
		this.controller = c;
		this.manager = c.getPluginManager();
		model = new PluginTreeModel(manager, this);
		this.setModel(model);
		this.setRootVisible(false);
		this.setCellRenderer(new PluginTreeCellRenderer());
		this.getCheckingModel().setCheckingMode(TreeCheckingModel.CheckingMode.PROPAGATE_PRESERVING_CHECK);
		this.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);

		this.addTreeCheckingListener(new TreeCheckingListener() {
			@Override
			public void valueChanged(TreeCheckingEvent e) {
				Object o = e.getPath().getLastPathComponent();
				if (o instanceof AbstractPlugin) {
					controller.setPluginActive(((AbstractPlugin) o).getName(),
							e.isCheckedPath());
				} 
				else if (o.getClass().isAssignableFrom(
						getModel().getRoot().getClass())) {
					Object node = model.getRoot();
					Object[] path = e.getPath().getPath();
					for (int i = 1; i < path.length; ++i) {
						node = model.getChild(node,
								model.getIndexOfChild(node, path[i]));
					}
					if (node instanceof Category<?, ?>) {
						@SuppressWarnings("unchecked")
						Category<String, AbstractPlugin> category = (Category<String, AbstractPlugin>) node;
						List<AbstractPlugin> list = category
								.getLeafsRecursive();
						for (AbstractPlugin plugin : list) {
							controller.setPluginActive(plugin.getName(),
									e.isCheckedPath());
						}
					}
				}
				repaint();
			}
		});
	}
	
	class PluginTreeCellRenderer extends DefaultCheckboxTreeCellRenderer {

		private static final long serialVersionUID = 1L;

		@SuppressWarnings("unchecked")
		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value,
				boolean selected, boolean expanded, boolean leaf, int row,
				boolean hasFocus) {
			Component defaultCell = super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
			JLabel additionalText = new JLabel();
			additionalText.setFont(new java.awt.Font("Dialog",2,12));
			JPanel newCell = new JPanel();
			newCell.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));
			newCell.setOpaque(false);
			newCell.add(defaultCell);
			newCell.add(additionalText);
			
			if(value.getClass().isAssignableFrom(model.getRoot().getClass())) {
				additionalText.setText(String.format("(%d)",((Category<String, AbstractPlugin>) value).getLeafsRecursive().size()));
			} else if (value instanceof AbstractPlugin) {
				AbstractPlugin plugin = (AbstractPlugin) value;
				additionalText.setText(String.format("(%s)", plugin.getState()));
			} else {
				System.out.println("Does not expect class: " + value.getClass());
			}
			
			return newCell;
		}
	}

	class PluginTreeModel extends AbstractTreeModel implements
			PluginManagerListener {
		CheckboxTree tree;
		PluginManager manager;
		Category<String,AbstractPlugin> rootCategory, allCategory, activeCategory, abcCategory;
		
		public PluginTreeModel(PluginManager pluginManager, CheckboxTree tree) {
			manager = pluginManager;
			manager.addListener(this);
			this.tree = tree;

			rootCategory = new PluginCategory("root");
			
			allCategory = new PluginCategory("All Plugins");
			activeCategory = new PluginCategory("Active Plugins");
			abcCategory = new PluginCategory("Alphabetical Sorted");

			allCategory = rootCategory.addCategory(allCategory);
			activeCategory = rootCategory.addCategory(activeCategory);
			abcCategory = rootCategory.addCategory(abcCategory);
			
//			activeCategory = rootCategory.getSubCategory("Active Plugins");
//			allCategory = rootCategory.getSubCategory("All Plugins");
//			abcCategory = rootCategory.getSubCategory("Alphabetical Sorted");

			pluginContainerChanged();
		}

		@SuppressWarnings("unchecked")
		@Override
		public Object getChild(Object parent, int index) {
			if (parent.getClass().isAssignableFrom(rootCategory.getClass())) {
				return ((Category<String, AbstractPlugin>) parent)
						.getNode(index);
			}
			return null;
		}

		@SuppressWarnings("unchecked")
		@Override
		public int getChildCount(Object node) {
			int count = 0;
			if (node.getClass().isAssignableFrom(rootCategory.getClass())) {
				count = ((Category<String, AbstractPlugin>) node).countNodes();
			}
			return count;
		}

		@SuppressWarnings("unchecked")
		@Override
		public int getIndexOfChild(Object parent, Object node) {
			if (parent.getClass().isAssignableFrom(rootCategory.getClass())) {
				return ((Category<String, AbstractPlugin>) parent)
						.getIndexOfNode(node);
			}
			return 0;
		}

		@Override
		public Object getRoot() {
			return rootCategory;
		}

		@Override
		public boolean isLeaf(Object arg0) {
			if (arg0 instanceof AbstractPlugin) {
				return true;
			}
			return false;
		}

		@Override
		public void valueForPathChanged(TreePath path, Object newValue) {
			System.out.println("### WARNING ###");
		}

		@Override
		public void currentPointsChanged(AbstractPlugin plugin, int newPoints) {
		}

		@Override
		public void pluginStateChanged(AbstractPlugin plugin,
				PluginState newState, PluginState oldState) {
			tree.repaint();
		}

		@Override
		public synchronized void pluginActiveStateChanged(AbstractPlugin plugin,
				boolean active) {

			System.out.println("### Checked Pre:");
			for(TreePath x : tree.getCheckingPaths()) {
				System.out.println("    " + x);
			}
			
			Category<String, AbstractPlugin> zwerg = allCategory;
			TreePath allPath = new TreePath(new Object[] {rootCategory, allCategory});
			for(String key : plugin.getCategory()) {
				zwerg = zwerg.getSubCategory(key);
				if(zwerg == null) {
					System.out.println("Error finding path");
					return;
				}
				allPath = allPath.pathByAddingChild(zwerg);
			}
			allPath = allPath.pathByAddingChild(plugin);
			TreePath activePath = new TreePath(new Object[] {rootCategory, activeCategory, plugin});
			TreePath abcPath = new TreePath(new Object[] {rootCategory, abcCategory, plugin});
			
			if (active) {
				if (activeCategory.addLeaf(plugin)) {
					fireChildAdded(activePath.getParentPath(), activeCategory.getIndexOfNode(plugin), plugin);
					tree.addCheckingPath(allPath);
					tree.addCheckingPath(activePath.getParentPath());
					tree.addCheckingPath(abcPath);
				}
			}
			else {
				int index =  activeCategory.getIndexOfNode(plugin);
				if (activeCategory.removeLeaf(plugin)) {
					tree.removeCheckingPath(allPath);
					tree.removeCheckingPath(activePath);
					tree.removeCheckingPath(abcPath);
					fireChildRemoved(activePath.getParentPath(), index, plugin);
				}
			}
			System.out.println("### Checked After:");
			for(TreePath x : tree.getCheckingPaths()) {
				System.out.println("    " + x + " " + x.getLastPathComponent().getClass());
			}
//			rootCategory.print();
//			tree.repaint();
//			tree.updateUI();
			for(int i = 0; i < tree.getRowCount(); ++i) {
				TreePath x = tree.getPathForRow(i);
				boolean checked = tree.getCheckingModel().isPathChecked(x);
				boolean enabled = tree.getCheckingModel().isPathEnabled(x);
				boolean greyed = tree.getCheckingModel().isPathGreyed(x);
				System.out.println(x + (checked?" (Checked)":"") + (enabled?" (Enabled)":"") + (greyed?" (Greyed)":""));
			}
		}

		@Override
		public synchronized void pluginContainerChanged() {
			allCategory.removeAllNodes(true);
			abcCategory.removeAllNodes(true);
			activeCategory.removeAllNodes(true);
			Iterator<AbstractPlugin> it = manager.getPluginIterator();
			while (it.hasNext()) {
				AbstractPlugin plugin = it.next();
				allCategory.createPath(plugin.getCategory()).addLeaf(plugin);
				abcCategory.addLeaf(plugin);
			}
			fireNewRoot();
		}
	}
}
