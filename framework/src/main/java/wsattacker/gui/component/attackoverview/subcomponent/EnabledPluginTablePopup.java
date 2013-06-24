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
package wsattacker.gui.component.attackoverview.subcomponent;

import java.awt.AWTEvent;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginFunctionInterface;
import wsattacker.main.plugin.PluginManager;

class EnabledPluginTablePopup extends JPopupMenu {

	class ActionListenerHelper implements ActionListener {

		private PluginFunctionInterface function;

		public ActionListenerHelper(PluginFunctionInterface function) {
			this.function = function;
		}

		@Override
		public void actionPerformed(ActionEvent ae) {
			function.getGuiWindow().setVisible(true);
		}

	}

	public EnabledPluginTablePopup() {
		System.out.println("### POPUP ###");
		addPopupMenuListener(new PopupMenuListener() {
			private void maybeUpdateSelection(PopupMenuEvent e) {
				final AWTEvent awtEvent = EventQueue.getCurrentEvent();
				final MouseEvent me;
				if (!( awtEvent instanceof MouseEvent )
						|| !( me = (MouseEvent) awtEvent ).isPopupTrigger()) {
					return;
				}
				final JPopupMenu menu = (JPopupMenu) e.getSource();
				final Component invoker = menu.getInvoker();

				if (!( invoker instanceof JTable )) {
					return;
				}
				final JTable table = (JTable) invoker;
				final Point p = me.getPoint();
				final int row = table.rowAtPoint(p);
				final int col = table.columnAtPoint(p);
				if (row == -1 || col == -1) {
					return;
				}
				// EventUtils.isCtrlOrMetaDown(me) am besten machst hier noch so eine methode, da bei MAC
				// die Metda down Taste verwendet wird...
//				table.changeSelection(row, col, me.CtrlDown(), me.isShiftDown());
				removeAll();
				AbstractPlugin plugin = PluginManager.getInstance().getActive(row);
				JMenu pluginmenu = new JMenu(plugin.getName());
				for (PluginFunctionInterface function : plugin.getPluginFunctionList()) {
					JMenuItem item = new JMenuItem(function.getName());
					item.addActionListener(new ActionListenerHelper(function));
					item.setEnabled(function.isEnabled());
					pluginmenu.add(item);
				}
				add(pluginmenu);
			}

			public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
				maybeUpdateSelection(e);
			}

			public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
				maybeUpdateSelection(e);
			}

			public void popupMenuCanceled(PopupMenuEvent e) {
				maybeUpdateSelection(e);
			}
		});
	}
}
