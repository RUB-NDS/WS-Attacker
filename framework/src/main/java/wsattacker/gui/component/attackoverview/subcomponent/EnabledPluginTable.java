/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010 Christian Mainka
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
package wsattacker.gui.component.attackoverview.subcomponent;

import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import wsattacker.gui.util.CenteredTableCellRenderer;
import wsattacker.gui.util.ColoredPluginStateTableCellRenderer;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginManagerListener;
import wsattacker.main.plugin.PluginManager;
import wsattacker.main.plugin.PluginState;

public class EnabledPluginTable extends JTable {

    public EnabledPluginTable() {
        setModel(new AttackOverviewTableModel());
        getColumnModel().getColumn(0).setCellRenderer(new CenteredTableCellRenderer());
        getColumnModel().getColumn(1).setCellRenderer(new ColoredPluginStateTableCellRenderer());
        getColumnModel().getColumn(2).setCellRenderer(new CenteredTableCellRenderer());
        getColumnModel().getColumn(3).setCellRenderer(new CenteredTableCellRenderer());
//        getColumnModel().getColumn(4).setCellRenderer(new VulnerableTableCellRenderer());
		setComponentPopupMenu(new EnabledPluginTablePopup());
    }

    @SuppressWarnings("serial")
    public class AttackOverviewTableModel extends AbstractTableModel implements
            PluginManagerListener {

//        final private String[] columnNames = {"Name", "Status", "Current", "Max", "Vulnerable?"};
        final private String[] columnNames = {"Name", "Status", "Rating", "Vulnerable?"};
        final PluginManager pluginManager;

        public AttackOverviewTableModel() {
            this.pluginManager = PluginManager.getInstance();
            this.pluginManager.addListener(this);
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
            return pluginManager.countActivePlugins();
        }

        @Override
        public Object getValueAt(int row, int col) {
            final AbstractPlugin plugin = pluginManager.getActive(row);
            switch (col) {
                case 0:
                    return plugin.getName();
                case 1:
                    return plugin.getState();
                case 2:
					return String.format("%d%%", 100*plugin.getCurrentPoints()/plugin.getMaxPoints());
                case 3:
                    return new Boolean(plugin.wasSuccessful());
            }
            return null;
        }

        @SuppressWarnings({"rawtypes", "unchecked"})
        @Override
        public Class getColumnClass(int c) {
            return getValueAt(0, c).getClass();
        }

        @Override
        public void currentPointsChanged(AbstractPlugin plugin, int newPoints) {
            int row = pluginManager.indexOfActive(plugin);
            this.fireTableCellUpdated(row, 2);
        }

        @Override
        public void pluginStateChanged(AbstractPlugin plugin,
                PluginState newState, PluginState oldState) {
            if (pluginManager.isActive(plugin)) {
                int row = pluginManager.indexOfActive(plugin);
                this.fireTableCellUpdated(row, 1);
                this.fireTableCellUpdated(row, 3);
            }
        }

        @Override
        public void pluginActiveStateChanged(AbstractPlugin plugin,
                boolean active) {
            if (active) {
                int row = pluginManager.indexOf(plugin);
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
}
