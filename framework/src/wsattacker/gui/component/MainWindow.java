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

package wsattacker.gui.component;
import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.GroupLayout;
import javax.swing.JComponent;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.LayoutStyle;
import javax.swing.WindowConstants;

import wsattacker.gui.component.log.GuiAppender;
import wsattacker.gui.component.log.StatuslineGUI;

/**
* This code was edited or generated using CloudGarden's Jigloo
* SWT/Swing GUI Builder, which is free for non-commercial
* use. If Jigloo is being used commercially (ie, by a corporation,
* company or business for any purpose whatever) then you
* should purchase a license for each developer using Jigloo.
* Please visit www.cloudgarden.com for details.
* Use of Jigloo implies acceptance of these licensing terms.
* A COMMERCIAL LICENSE HAS NOT BEEN PURCHASED FOR
* THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED
* LEGALLY FOR ANY CORPORATE OR COMMERCIAL PURPOSE.
*/
public class MainWindow extends javax.swing.JFrame {
	private static final long serialVersionUID = 1L;
	private StatuslineGUI statusline;
	private JMenuBar menu;
	private JMenu jMenu1;
	private AbstractAction exitAction;
	private JMenuItem exit;
	private JSeparator jSeparator1;
	private JTabbedPane tabs;
	
	public MainWindow() {
		super();
		initGUI();
	}
	
	private void initGUI() {
		try {
			GroupLayout thisLayout = new GroupLayout((JComponent)getContentPane());
			getContentPane().setLayout(thisLayout);
			setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
			this.setPreferredSize(new java.awt.Dimension(800, 600));
			{
				statusline = GuiAppender.getStatusbar();
			}
			{
				tabs = new JTabbedPane();
			}
			thisLayout.setVerticalGroup(thisLayout.createSequentialGroup()
				.addContainerGap()
				.addComponent(getTabsx(), 0, 312, Short.MAX_VALUE)
				.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED, 1, GroupLayout.PREFERRED_SIZE)
				.addComponent(statusline, GroupLayout.PREFERRED_SIZE, 18, GroupLayout.PREFERRED_SIZE)
				.addContainerGap());
			thisLayout.setHorizontalGroup(thisLayout.createSequentialGroup()
				.addContainerGap()
				.addGroup(thisLayout.createParallelGroup()
				    .addComponent(statusline, GroupLayout.Alignment.LEADING, 0, 448, Short.MAX_VALUE)
				    .addComponent(getTabsx(), GroupLayout.Alignment.LEADING, 0, 448, Short.MAX_VALUE))
				.addContainerGap());
			{
				menu = new JMenuBar();
				setJMenuBar(getMenu());
				{
					jMenu1 = new JMenu();
					menu.add(jMenu1);
					jMenu1.setText("File");
					{
						jSeparator1 = new JSeparator();
						jMenu1.add(jSeparator1);
					}
					{
						exit = new JMenuItem();
						jMenu1.add(exit);
						exit.setText("Exit");
						exit.setAction(getExitAction());
					}
				}
			}
			this.setSize(472, 391);
		} catch (Exception e) {
		    //add your error handling code here
			e.printStackTrace();
		}
	}
	
	public JTabbedPane getTabs() {
		return tabs;
	}

	public StatuslineGUI getStatusline() {
		return statusline;
	}
	
	public JMenuBar getMenu() {
		return menu;
	}
	
	public JTabbedPane getTabsx() {
		return tabs;
	}
	
	@SuppressWarnings("serial")
	private AbstractAction getExitAction() {
		if(exitAction == null) {
			exitAction = new AbstractAction("Exit", null) {
				public void actionPerformed(ActionEvent evt) {
					System.exit(0);
				}
			};
		}
		return exitAction;
	}

}
