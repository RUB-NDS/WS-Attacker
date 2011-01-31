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

package wsattacker.gui.util;

import java.awt.Component;
import java.awt.Font;

import javax.swing.JLabel;
import javax.swing.JTable;

import wsattacker.main.plugin.PluginState;

public class VulnerableTableCellRenderer extends CenteredTableCellRenderer {

	public VulnerableTableCellRenderer() {
	}
	
	@Override
	public Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int column) {
		JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
		
		Object status = table.getModel().getValueAt(row, 1);
		if(status.toString().equals(PluginState.Finished.toString()) && value instanceof Boolean) {
			Boolean succ = (Boolean) value;
			if(succ.booleanValue()) {
				c.setBackground(Colors.INVALID);
				c.setFont(new java.awt.Font("Dialog",Font.BOLD,12));
				c.setOpaque(true);
				c.setText("YES");
			}
			else {
				c.setFont(new java.awt.Font("Dialog",Font.ITALIC,12));
				c.setText("no");
			}
		} else {
			c.setText("");
		}
		
		return c;
	}
}
