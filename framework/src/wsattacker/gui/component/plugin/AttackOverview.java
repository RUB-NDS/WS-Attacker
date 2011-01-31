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
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.LayoutStyle;
import javax.swing.SwingConstants;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;

import wsattacker.gui.component.plugin.subcomponent.ResultTable;
import wsattacker.gui.util.CenteredTableCellRenderer;
import wsattacker.gui.util.ColoredPluginStateTableCellRenderer;
import wsattacker.gui.util.VulnerableTableCellRenderer;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginManagerListener;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.result.ResultLevel;

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
public class AttackOverview extends javax.swing.JPanel {
	private static final long serialVersionUID = 1L;
	private JTable pluginTable;
	private JScrollPane pluginTableScrollPane;
	private ResultTable resultTable;
	private JSlider resultLevelSlider;
	private JButton stop;
	private JSplitPane splitPane;
	private AbstractAction cleanResultsAction;
	private JButton clean;
	private JScrollPane resultsScrollPane;
	private AbstractAction stopAttackAction;
	private AbstractAction startAttackAction;
	private JButton start;

	private ControllerInterface controller;

	public AttackOverview(ControllerInterface controller) {
		super();
		this.controller = controller;
		setName("Attack Overview");
		// controller.getPluginManager().addListener(this);
		// TestSuite.getInstance().getCurrentRequest().addCurrentRequestObserver(this);
		initGUI();
	}

	private void initGUI() {
		try {
			getJSplitPane1(); // for initialisation
			GroupLayout thisLayout = new GroupLayout((JComponent) this);
			this.setLayout(thisLayout);
			this.setPreferredSize(new java.awt.Dimension(868, 346));
			{
				start = new JButton();
				start.setText("Start Attack");
				start.setAction(getStartAttackAction());
				// start.setEnabled(false);
			}
			{
				stop = new JButton();
				stop.setText("Stop Attack");
				stop.setAction(getStopAttackAction());
				// stop.setEnabled(false);
			}
			thisLayout
					.setVerticalGroup(thisLayout
							.createSequentialGroup()
							.addContainerGap()
							.addGroup(
									thisLayout
											.createParallelGroup()
											.addGroup(
													GroupLayout.Alignment.LEADING,
													thisLayout
															.createParallelGroup(
																	GroupLayout.Alignment.BASELINE)
															.addComponent(
																	start,
																	GroupLayout.Alignment.BASELINE,
																	GroupLayout.PREFERRED_SIZE,
																	GroupLayout.PREFERRED_SIZE,
																	GroupLayout.PREFERRED_SIZE)
															.addComponent(
																	stop,
																	GroupLayout.Alignment.BASELINE,
																	GroupLayout.PREFERRED_SIZE,
																	GroupLayout.PREFERRED_SIZE,
																	GroupLayout.PREFERRED_SIZE)
															.addComponent(
																	getClean(),
																	GroupLayout.Alignment.BASELINE,
																	GroupLayout.PREFERRED_SIZE,
																	GroupLayout.PREFERRED_SIZE,
																	GroupLayout.PREFERRED_SIZE))
											.addComponent(
													getResultLevelSlider(),
													GroupLayout.Alignment.LEADING,
													GroupLayout.PREFERRED_SIZE,
													35,
													GroupLayout.PREFERRED_SIZE))
							.addPreferredGap(
									LayoutStyle.ComponentPlacement.RELATED)
							.addComponent(getJSplitPane1(), 0, 281,
									Short.MAX_VALUE).addContainerGap());
			thisLayout
					.setHorizontalGroup(thisLayout
							.createSequentialGroup()
							.addContainerGap()
							.addGroup(
									thisLayout
											.createParallelGroup()
											.addGroup(
													GroupLayout.Alignment.LEADING,
													thisLayout
															.createSequentialGroup()
															.addComponent(
																	start,
																	GroupLayout.PREFERRED_SIZE,
																	149,
																	GroupLayout.PREFERRED_SIZE)
															.addPreferredGap(
																	LayoutStyle.ComponentPlacement.UNRELATED)
															.addComponent(
																	stop,
																	GroupLayout.PREFERRED_SIZE,
																	149,
																	GroupLayout.PREFERRED_SIZE)
															.addPreferredGap(
																	LayoutStyle.ComponentPlacement.UNRELATED)
															.addComponent(
																	getClean(),
																	GroupLayout.PREFERRED_SIZE,
																	149,
																	GroupLayout.PREFERRED_SIZE)
															.addGap(0,
																	66,
																	Short.MAX_VALUE)
															.addComponent(
																	getResultLevelSlider(),
																	GroupLayout.PREFERRED_SIZE,
																	309,
																	GroupLayout.PREFERRED_SIZE))
											.addComponent(
													getJSplitPane1(),
													GroupLayout.Alignment.LEADING,
													0, 844, Short.MAX_VALUE))
							.addContainerGap());
			thisLayout.linkSize(SwingConstants.VERTICAL, new Component[] {
					stop, start });
			thisLayout.linkSize(SwingConstants.HORIZONTAL, new Component[] {
					getClean(), stop, start });
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public JTable getPluginTable() {
		return pluginTable;
	}

	@SuppressWarnings("serial")
	private AbstractAction getStartAttackAction() {
		if (startAttackAction == null) {
			startAttackAction = new AbstractAction("Start Attack", null) {
				public void actionPerformed(ActionEvent evt) {
					controller.startActivePlugins();
				}
			};
		}
		return startAttackAction;
	}

	@SuppressWarnings("serial")
	private AbstractAction getStopAttackAction() {
		if (stopAttackAction == null) {
			stopAttackAction = new AbstractAction("Stop Attack", null) {
				public void actionPerformed(ActionEvent evt) {
					controller.stopActivePlugins();
				}
			};
		}
		return stopAttackAction;
	}

	private JButton getClean() {
		if (clean == null) {
			clean = new JButton();
			clean.setText("Clean Results");
			clean.setAction(getCleanResultsAction());
			// clean.setEnabled(false);
		}
		return clean;
	}

	@SuppressWarnings("serial")
	private AbstractAction getCleanResultsAction() {
		if (cleanResultsAction == null) {
			cleanResultsAction = new AbstractAction("Clean Results", null) {
				public void actionPerformed(ActionEvent evt) {
					controller.cleanPlugins();
				}
			};
		}
		return cleanResultsAction;
	}

	private JSlider getResultLevelSlider() {
		if (resultLevelSlider == null) {
			resultLevelSlider = new JSlider();
			Dictionary<Integer, JLabel> labelTable = new Hashtable<Integer, JLabel>();
			ResultLevel[] levels = ResultLevel.values(); // get all result
															// levels
			int max = levels.length - 1;
			resultLevelSlider.setMinimum(0);
			resultLevelSlider.setMaximum(max);
			for (int i = max; i >= 0; --i) {
				labelTable.put(i, new JLabel(levels[i].toString())); // add each
																		// to
																		// the
																		// slider
			}
			resultLevelSlider.setLabelTable(labelTable);
			resultLevelSlider.setPaintLabels(true);
			resultLevelSlider.setSnapToTicks(true);
			// add change listener
			resultLevelSlider.addChangeListener(new ChangeListener() {

				@Override
				public void stateChanged(ChangeEvent e) {
					int val = resultLevelSlider.getValue();
					String level = ((JLabel) resultLevelSlider.getLabelTable()
							.get(val)).getText();
					resultTable.setLevel(ResultLevel.valueOf(level));

				}
			});
			resultLevelSlider.setValue(max / 2); // set default level
		}
		return resultLevelSlider;
	}

	private JSplitPane getJSplitPane1() {
		if (splitPane == null) {
			splitPane = new JSplitPane();
			splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
			{
				pluginTableScrollPane = new JScrollPane();
				splitPane.add(pluginTableScrollPane, JSplitPane.TOP);
				{
					pluginTable = new JTable();
					pluginTableScrollPane.setViewportView(pluginTable);
					pluginTable.setModel(new AttackOverviewTableModel());
					pluginTable.getSelectionModel().addListSelectionListener(
							new ListSelectionListener() {
								@Override
								public void valueChanged(ListSelectionEvent e) {
									if (!e.getValueIsAdjusting()) {
										int[] selected = pluginTable
												.getSelectedRows();
										List<String> sources = new ArrayList<String>();
										for (int index : selected) {
											sources.add(controller
													.getPluginManager()
													.getActive(index)
													.getName());
										}
										resultTable.filterSources(sources);
									}
								}
							});
					pluginTable.getColumnModel().getColumn(0)
							.setCellRenderer(new CenteredTableCellRenderer());
					pluginTable
							.getColumnModel()
							.getColumn(1)
							.setCellRenderer(
									new ColoredPluginStateTableCellRenderer());
					pluginTable.getColumnModel().getColumn(2)
							.setCellRenderer(new CenteredTableCellRenderer());
					pluginTable.getColumnModel().getColumn(3)
							.setCellRenderer(new CenteredTableCellRenderer());
					pluginTable.getColumnModel().getColumn(4)
							.setCellRenderer(new VulnerableTableCellRenderer());
				}
			}
			{
				resultsScrollPane = new JScrollPane();
				splitPane.add(resultsScrollPane, JSplitPane.BOTTOM);
				{
					resultTable = new ResultTable();
					resultsScrollPane.setViewportView(resultTable);
				}
			}
		}
		return splitPane;
	}

	@SuppressWarnings("serial")
	public class AttackOverviewTableModel extends AbstractTableModel implements
			PluginManagerListener {

		final private String[] columnNames = { "Name", "Status", "Current",
				"Max", "Vulnerable?" };

		public AttackOverviewTableModel() {
			controller.getPluginManager().addListener(this);
		}

		@Override
		public int getColumnCount() {
			return columnNames.length;
		}

		@Override
		public String getColumnName(int num) {
			return this.columnNames[num];
		}

		@Override
		public boolean isCellEditable(int y, int x) {
			return false;
		}

		@Override
		public int getRowCount() {
			return controller.getPluginManager().countActivePlugins();
		}

		@Override
		public Object getValueAt(int row, int col) {
			AbstractPlugin plugin = controller.getPluginManager()
					.getActive(row);
			switch (col) {
			case 0:
				return plugin.getName();
			case 1:
				return plugin.getState();
			case 2:
				return new Integer(plugin.getCurrentPoints());
			case 3:
				return new Integer(plugin.getMaxPoints());
			case 4:
				return new Boolean(plugin.wasSuccessful());
			}
			return null;
		}

		@SuppressWarnings({ "rawtypes", "unchecked" })
		@Override
		public Class getColumnClass(int c) {
			return getValueAt(0, c).getClass();
		}

		@Override
		public void currentPointsChanged(AbstractPlugin plugin, int newPoints) {
			int row = controller.getPluginManager().indexOfActive(plugin);
			this.fireTableCellUpdated(row, 2);
		}

		@Override
		public void pluginStateChanged(AbstractPlugin plugin,
				PluginState newState, PluginState oldState) {
			if (controller.getPluginManager().isActive(plugin)) {
				int row = controller.getPluginManager().indexOfActive(plugin);
				this.fireTableCellUpdated(row, 1);
				this.fireTableCellUpdated(row, 4);
			}
		}

		@Override
		public void pluginActiveStateChanged(AbstractPlugin plugin,
				boolean active) {
			if (active) {
				int row = controller.getPluginManager().indexOf(plugin);
				fireTableRowsInserted(row, row);
			} else {
				fireTableDataChanged(); // no chance to detect row
			}
		}

		@Override
		public void pluginContainerChanged() {
			fireTableDataChanged();
		}
	}
	//
	// private void configureButtons() {
	// // if one pluginstate changed, we check all plugins if any buttons may
	// // be enabled or disabled
	// boolean allReady = true;
	// boolean allFinished = true;
	// boolean oneRunning = false;
	// AbstractPlugin p;
	// Iterator<AbstractPlugin> it = controller.getPluginManager()
	// .getActivePluginIterator();
	// while (it.hasNext()) {
	// p = it.next();
	// allReady &= p.isReady();
	// allFinished &= p.isFinished();
	// oneRunning |= p.isRunning();
	// }
	// WsdlRequest request = TestSuite.getInstance().getCurrentRequest()
	// .getWsdlRequest();
	// boolean hasResponse = (request != null)
	// && (request.getResponse() != null);
	// start.setEnabled(allReady && !oneRunning && !allFinished && hasResponse);
	// stop.setEnabled(oneRunning);
	// clean.setEnabled(!oneRunning && (Result.getGlobalResult().size() > 0));
	// }
	//
	// @Override
	// public void currentPointsChanged(AbstractPlugin plugin, int newPoints) {
	// // nothing to do
	// }
	//
	// @Override
	// public void pluginStateChanged(AbstractPlugin plugin, PluginState
	// newState,
	// PluginState oldState) {
	// configureButtons();
	// }
	//
	// @Override
	// public void currentRequestChanged(WsdlRequest newRequest,
	// WsdlRequest oldRequest) {
	// configureButtons();
	// }
	//
	// @Override
	// public void noCurrentRequest() {
	// start.setEnabled(false);
	// }
	//
	// @Override
	// public void pluginActiveStateChanged(AbstractPlugin plugin, boolean
	// active) {
	// configureButtons();
	// }
	//
	// @Override
	// public void pluginContainerChanged() {
	// // nothing to do
	// }
}
