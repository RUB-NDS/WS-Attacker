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

package wsattacker.gui.component.plugin;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

import javax.swing.AbstractAction;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextPane;
import javax.swing.JTree;
import javax.swing.LayoutStyle;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import org.apache.log4j.Logger;

import sun.print.PSPrinterJob.PluginPrinter;

import wsattacker.gui.GuiController;
import wsattacker.gui.component.plugin.option.OptionBooleanGUI;
import wsattacker.gui.component.plugin.option.OptionChoiceGUI;
import wsattacker.gui.component.plugin.option.OptionFileGUI;
import wsattacker.gui.component.plugin.option.OptionMultiLineGUI;
import wsattacker.gui.component.plugin.option.OptionSingleLineGUI;
import wsattacker.gui.component.plugin.subcomponent.PluginTree;
import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginManagerListener;
import wsattacker.main.composition.plugin.PluginOptionContainerObserver;
import wsattacker.main.composition.plugin.PluginOptionValueObserver;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.plugin.option.AbstractOptionBoolean;
import wsattacker.main.composition.plugin.option.AbstractOptionChoice;
import wsattacker.main.composition.plugin.option.AbstractOptionComplex;
import wsattacker.main.composition.plugin.option.AbstractOptionFile;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.plugin.option.AbstractOptionString;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;
import wsattacker.main.plugin.PluginOptionContainer;
import wsattacker.main.plugin.PluginState;

/**
 * This code was edited or generated using CloudGarden's Jigloo SWT/Swing GUI
 * Builder, which is free for non-commercial use. If Jigloo is being used
 * commercially (ie, by a corporation, company or business for any purpose
 * whatever) then you should purchase a license for each developer using Jigloo.
 * Please visit www.cloudgarden.com for details. Use of Jigloo implies
 * acceptance of these licensing terms. A COMMERCIAL LICENSE HAS NOT BEEN
 * PURCHASED FOR THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED LEGALLY FOR
 * ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
@SuppressWarnings("serial")
public class PluginConfigurationGUI extends javax.swing.JPanel implements
		PluginOptionContainerObserver, PluginOptionValueObserver {
	private JTable pluginTable;
	private JScrollPane pluginTableScrollPane;
	private JButton noneButton;
	private JPanel pluginOptionsPanel;
	private Box optionBox;
	private AbstractAction deactivateAllButton;
	private AbstractAction activeateAllButton;
	private JButton allButton;

	private Map<AbstractOption, AbstractOptionGUI> currentOptions = new HashMap<AbstractOption, AbstractOptionGUI>();
	private AbstractPlugin currentPlugin = null;
	private JScrollPane pluginOptionsPanelScrollBar;
	private JScrollPane plugintreeScrollPane;
	private PluginTree pluginTree;
	private AbstractAction load;
	private AbstractAction save;
	private JButton loadButton;
	private JButton saveBotton;
	private JFileChooser chooser;

	private JLabel pluginName;
	private JTextPane pluginDescription;

	private ControllerInterface controller;

	private final static String CONFIGEXTENSION = new String(".ser");

	public PluginConfigurationGUI(ControllerInterface controller) {
		super();
		this.controller = controller;
		setName("Plugin Config");
		initGUI();
	}

	private void initGUI() {
		try {
			GroupLayout thisLayout = new GroupLayout((JComponent)this);
			this.setPreferredSize(new java.awt.Dimension(861, 300));
			this.setLayout(thisLayout);
			{
//				pluginDescription = new JEditorPane("text/html","Description");
				pluginDescription = new JTextPane();
				pluginDescription.setEditable(false);
				pluginDescription.setBackground(getBackground());
			}
			{
				optionBox = Box.createVerticalBox();
			}
			{
				chooser = new JFileChooser();
				chooser.setMultiSelectionEnabled(false);
				chooser.setAcceptAllFileFilterUsed(false);
				chooser.setFileFilter(new FileFilter() {

					@Override
					public String getDescription() {
						return CONFIGEXTENSION
								+ " - Plugin configuration files (Java object serialisation)";
					}

					@Override
					public boolean accept(File f) {
						// always show directories
						if (f.isDirectory()) {
							return true;
						}
						return f.toString().toLowerCase()
								.endsWith(CONFIGEXTENSION);
					}
				});
			}
			{
				pluginTableScrollPane = new JScrollPane();
				pluginTableScrollPane.setVisible(false);
				{
					TableModel pluginTableModel = new PluginConfigurationTableModel(
							controller);
					pluginTable = new JTable();
					pluginTableScrollPane.setViewportView(pluginTable);
					pluginTable.setModel(pluginTableModel);
					pluginTable.getColumnModel().getColumn(0)
							.setPreferredWidth(200);
					pluginTable.getColumnModel().getColumn(1)
							.setPreferredWidth(100);
					pluginTable.getColumnModel().getColumn(2)
							.setPreferredWidth(40);
					pluginTable
							.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
					pluginTable.getSelectionModel().addListSelectionListener(
							new ListSelectionListener() {
								@Override
								public void valueChanged(ListSelectionEvent e) {
									if (!e.getValueIsAdjusting()) {
										setPluginToConfigure(pluginTable
												.getSelectedRow());
									}
								}
							});

				}
			}
			{
				pluginName = new JLabel("Plugin Configuration");
				pluginName.setFont(new java.awt.Font("Dialog", 1, 14));
			}
			{
				allButton = new JButton();
				allButton.setText("All");
				allButton.setAction(getActiveateAllButton());
			}
			{
				noneButton = new JButton();
				noneButton.setText("None");
				noneButton.setAction(getDeactivateAllButton());
			}
			thisLayout.setVerticalGroup(thisLayout.createSequentialGroup()
				.addComponent(pluginTableScrollPane, GroupLayout.PREFERRED_SIZE, 10, GroupLayout.PREFERRED_SIZE)
				.addGroup(thisLayout.createParallelGroup()
				    .addGroup(thisLayout.createSequentialGroup()
				        .addComponent(pluginName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
				        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				        .addComponent(getJScrollPane1x(), 0, 265, Short.MAX_VALUE))
				    .addGroup(thisLayout.createSequentialGroup()
				        .addComponent(getJScrollPane1(), 0, 254, Short.MAX_VALUE)
				        .addGap(12)
				        .addGroup(thisLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
				            .addComponent(allButton, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
				            .addComponent(noneButton, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
				            .addComponent(getSaveBotton(), GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
				            .addComponent(getLoadButton(), GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))))
				.addContainerGap(12, 12));
			thisLayout.setHorizontalGroup(thisLayout.createSequentialGroup()
				.addComponent(pluginTableScrollPane, GroupLayout.PREFERRED_SIZE, 10, GroupLayout.PREFERRED_SIZE)
				.addGroup(thisLayout.createParallelGroup()
				    .addGroup(thisLayout.createSequentialGroup()
				        .addComponent(allButton, GroupLayout.PREFERRED_SIZE, 83, GroupLayout.PREFERRED_SIZE)
				        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
				        .addComponent(noneButton, GroupLayout.PREFERRED_SIZE, 83, GroupLayout.PREFERRED_SIZE)
				        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
				        .addComponent(getSaveBotton(), GroupLayout.PREFERRED_SIZE, 83, GroupLayout.PREFERRED_SIZE)
				        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
				        .addComponent(getLoadButton(), GroupLayout.PREFERRED_SIZE, 83, GroupLayout.PREFERRED_SIZE))
				    .addComponent(getJScrollPane1(), GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 380, GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(thisLayout.createParallelGroup()
				    .addComponent(pluginName, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 457, GroupLayout.PREFERRED_SIZE)
				    .addComponent(getJScrollPane1x(), GroupLayout.Alignment.LEADING, 0, 457, Short.MAX_VALUE))
				.addContainerGap(12, 12));
			thisLayout.linkSize(SwingConstants.VERTICAL, new Component[] {noneButton, allButton});
			thisLayout.linkSize(SwingConstants.HORIZONTAL, new Component[] {allButton, noneButton, getSaveBotton(), getLoadButton()});
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void setPluginToConfigure(int index) {
		currentOptions.clear();

		if (currentPlugin != null) {
			currentPlugin.getPluginOptions()
					.removePluginOptionContainerObserver(this);
			currentPlugin.getPluginOptions()
					.removePluginValueContainerObserver(this);
		}
		currentPlugin = controller.getPluginManager().getByIndex(index);
		setPluginToConfigure(currentPlugin);
	}
	
	public void setPluginToConfigure(AbstractPlugin plugin) {
		currentPlugin = plugin;
		if (currentPlugin != null) {
			// name
			pluginName.setText(currentPlugin.getName());

			// description
			pluginDescription.setText(String.format("%-15s%s\n%-15s%s\n%-13s%d\n\n%s",
					"Author:", currentPlugin.getAuthor(),
					"Version:", currentPlugin.getVersion(),
					"Max Points:",currentPlugin.getMaxPoints(),
					currentPlugin.getDescription()));
			pluginDescription.setSize(Integer.MAX_VALUE, 500);

			// remove all components from view and logic container
			optionBox.removeAll();
			for (AbstractOption option : currentPlugin.getPluginOptions()) {
				try {
					AbstractOptionGUI optionGUI = createOption(option);
					currentOptions.put(option, optionGUI);
					// getPluginOptionsPanel().add(optionGUI);
					optionGUI.setPreferredSize(new Dimension(pluginOptionsPanel.getSize().width, optionGUI.getPreferredSize().height));
					optionGUI.setSize(optionGUI.getPreferredSize());
					optionBox.add(optionGUI);
				} catch (Exception e) {
					Logger.getLogger(getClass())
							.error(String
									.format("Could not create option panel for Option '%s' of Plugin '%s'. Errormessage: %s",
											option.getName(),
											currentPlugin.getName(),
											e.getMessage()));
				}
			}
			optionBox.revalidate();
			currentPlugin.getPluginOptions().addPluginOptionContainerObserver(
					this);
			currentPlugin.getPluginOptions().addPluginValueContainerObserver(
					this);
		}

	}

	private AbstractOptionGUI createOption(AbstractOption option) {
		AbstractOptionGUI optionGUI = null;
		// Although the following does not look very smart, it allows the user to
		// create simple options
		// by just extending AbstractOption*. This way, the user does not need
		// to take care about UI
		if (option instanceof AbstractOptionString) {
			if (option instanceof AbstractOptionVarchar) {
				optionGUI = new OptionSingleLineGUI(controller, currentPlugin,
						(AbstractOptionVarchar) option);
			} else {
				// default string component
				optionGUI = new OptionMultiLineGUI(controller, currentPlugin,
						(AbstractOptionString) option);
			}
		} else if (option instanceof AbstractOptionInteger) {
			optionGUI = new OptionSingleLineGUI(controller, currentPlugin,
					(AbstractOptionInteger) option);
		} else if (option instanceof AbstractOptionChoice) {
			optionGUI = new OptionChoiceGUI(controller, currentPlugin,
					(AbstractOptionChoice) option);
		} else if (option instanceof AbstractOptionBoolean) {
			optionGUI = new OptionBooleanGUI(controller, currentPlugin,
					(AbstractOptionBoolean) option);
		} else if (option instanceof AbstractOptionFile) {
			optionGUI = new OptionFileGUI(controller, currentPlugin,
					(AbstractOptionFile) option);
		}
		// for very complex options, plugin authors may create the UI for their
		// option himself
		else if (option instanceof AbstractOptionComplex) {
			optionGUI = ((AbstractOptionComplex) option).getComplexGUI(
					controller, currentPlugin);
		}
		// default component
		else {
			Logger.getLogger(getClass()).warn(
					"Coult not determine Type for option '" + option.getName()
							+ "', using default Input Method");
			optionGUI = new OptionMultiLineGUI(controller, currentPlugin,
					option);
		}
		return optionGUI;
	}

	public JPanel getPluginOptionsPanel() {
		return pluginOptionsPanel;
	}

	private AbstractAction getActiveateAllButton() {
		if (activeateAllButton == null) {
			activeateAllButton = new AbstractAction("All", null) {
				public void actionPerformed(ActionEvent evt) {
					controller.setAllPluginActive(true);
				}
			};
		}
		return activeateAllButton;
	}

	private AbstractAction getDeactivateAllButton() {
		if (deactivateAllButton == null) {
			deactivateAllButton = new AbstractAction("None", null) {
				public void actionPerformed(ActionEvent evt) {
					controller.setAllPluginActive(false);
				}
			};
		}
		return deactivateAllButton;
	}

	public class PluginConfigurationTableModel extends AbstractTableModel
			implements PluginManagerListener {

		private String[] columnNames = { "Name", "State", "Active" };
		private ControllerInterface controller;

		public PluginConfigurationTableModel(ControllerInterface controller) {
			this.controller = controller;
			this.controller.getPluginManager().addListener(this);
		}

		public String getColumnName(int num) {
			return this.columnNames[num];
		}

		@Override
		public int getColumnCount() {
			return this.columnNames.length;
		}

		@Override
		public int getRowCount() {
			return this.controller.getPluginManager().countPlugins();
		}

		@Override
		public Object getValueAt(int row, int col) {
			AbstractPlugin plugin = controller.getPluginManager().getByIndex(
					row);
			if (col == 0) {
				return plugin.getName();
			}
			if (col == 1) {
				return plugin.getState();
			}
			return new Boolean(controller.getPluginManager().isActive(plugin));
		}

		public boolean isCellEditable(int y, int x) {
			if (x == 2) {
				return true;
			}
			return false;
		}

		public void setValueAt(Object value, int row, int col) {
			Boolean active = (Boolean) value;
			controller.setPluginActive(row, active);
		}

		@SuppressWarnings({ "unchecked", "rawtypes" })
		public Class getColumnClass(int c) {
			return getValueAt(0, c).getClass();
		}

		@Override
		public void currentPointsChanged(AbstractPlugin plugin, int newPoints) {
			// nothing to do
		}

		@Override
		public void pluginStateChanged(AbstractPlugin plugin,
				PluginState newState, PluginState oldState) {
//			this.fireTableDataChanged();
			int row = controller.getPluginManager().indexOf(plugin);
			fireTableCellUpdated(row, 1);
		}

		@Override
		public void pluginActiveStateChanged(AbstractPlugin plugin,
				boolean active) {
			int row = controller.getPluginManager().indexOf(plugin);
			fireTableCellUpdated(row, 2);
		}

		@Override
		public void pluginContainerChanged() {
			fireTableDataChanged();
		}

	}

	@Override
	public void optionValueChanged(AbstractOption option) {
		Logger.getLogger(getClass()).debug("Reloading Option " + option.getName());
		currentOptions.get(option).reloadValue();
	}

	@Override
	public void optionContainerOptionAdded(PluginOptionContainer container,
			int index) {
		AbstractOption option = container.getByIndex(index);
		AbstractOptionGUI optionGUI = createOption(option);
		currentOptions.put(option, optionGUI);
		optionBox.add(optionGUI, index);
		optionBox.revalidate();
	}

	@Override
	public void optionContainerOptionRemoved(PluginOptionContainer container,
			AbstractOption removedOption) {
		AbstractOptionGUI removedOptiongGUI = currentOptions.get(removedOption);
		if (removedOptiongGUI != null) {
			currentOptions.remove(removedOption);
			optionBox.remove(removedOptiongGUI);
			// optionBox.updateUI();
		}
		optionBox.revalidate();

	}

	private JButton getSaveBotton() {
		if (saveBotton == null) {
			saveBotton = new JButton();
			saveBotton.setText("Save");
			saveBotton.setAction(getSave());
		}
		return saveBotton;
	}

	private JButton getLoadButton() {
		if (loadButton == null) {
			loadButton = new JButton();
			loadButton.setText("Load");
			loadButton.setAction(getLoad());
		}
		return loadButton;
	}

	private AbstractAction getSave() {
		if (save == null) {
			save = new AbstractAction("Save", null) {
				public void actionPerformed(ActionEvent evt) {
					Component c = (Component) evt.getSource();
					Component root = SwingUtilities.getRoot(c);
					chooser.showSaveDialog(root);
					File selected = chooser.getSelectedFile();
					if (selected != null) {
						if (!selected.toString().toLowerCase()
								.endsWith(CONFIGEXTENSION)) {
							selected.renameTo(new File(selected.toString()
									+ CONFIGEXTENSION));
						}
						controller.savePluginConfiguration(chooser
								.getSelectedFile());
					}
				}
			};
		}
		return save;
	}

	private AbstractAction getLoad() {
		if (load == null) {
			load = new AbstractAction("Load", null) {
				public void actionPerformed(ActionEvent evt) {
					Component c = (Component) evt.getSource();
					Component root = SwingUtilities.getRoot(c);
					chooser.showOpenDialog(root);
					File selected = chooser.getSelectedFile();
					if (selected != null) {
						controller.loadPluginConfiguration(selected);
					}
				}
			};
		}
		return load;
	}
	
	public JTree getPluginTree() {
		if(pluginTree == null) {
			pluginTree = new PluginTree(controller);
//			pluginTree.setBackground(getBackground());
			pluginTree.addTreeSelectionListener(new TreeSelectionListener() {
				
				@Override
				public void valueChanged(TreeSelectionEvent e) {
					Object o = e.getPath().getLastPathComponent();
					if(o instanceof AbstractPlugin) {
						setPluginToConfigure((AbstractPlugin) o);
					}
				}
			});
		}
		return pluginTree;
	}
	
	private JScrollPane getJScrollPane1() {
		if(plugintreeScrollPane == null) {
			plugintreeScrollPane = new JScrollPane();
			plugintreeScrollPane.setViewportView(getPluginTree());
		}
		return plugintreeScrollPane;
	}
	
	private JScrollPane getJScrollPane1x() {
		if(pluginOptionsPanelScrollBar == null) {
			pluginOptionsPanelScrollBar = new JScrollPane();
			{
				pluginOptionsPanel = new JPanel();
				pluginOptionsPanelScrollBar.setViewportView(pluginOptionsPanel);
				pluginOptionsPanelScrollBar.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
				BoxLayout pluginOptionsPanelLayout = new BoxLayout(
						pluginOptionsPanel, javax.swing.BoxLayout.Y_AXIS);
				pluginOptionsPanel.setLayout(pluginOptionsPanelLayout);
				pluginOptionsPanel.add(pluginDescription);
				pluginOptionsPanel.add(optionBox);
				
				// just as a glue (Box.createHorizontalGlue() does not work)
				JEditorPane filler = new JEditorPane();
				filler.setBackground(getBackground());
				filler.setEditable(false);
				pluginOptionsPanel.add(filler);
			}
		}
		return pluginOptionsPanelScrollBar;
	}
}
