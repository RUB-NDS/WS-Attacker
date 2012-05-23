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

package wsattacker.gui.component.plugin.option;

import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JScrollPane;
import javax.swing.LayoutStyle;

import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.gui.util.Colors;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;


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
public class OptionMultiLineGUI extends AbstractOptionGUI {
	private static final long serialVersionUID = 1L;
	private JEditorPane value;
	private JEditorPane name;
	private JEditorPane description;
	private JScrollPane valueScrollPane;
	private JScrollPane descriptionScrollPane;
	private JScrollPane nameScrollPane;
	
	public OptionMultiLineGUI(ControllerInterface controller, AbstractPlugin plugin, AbstractOption option) {
		super(controller, plugin, option);
		GroupLayout thisLayout = new GroupLayout((JComponent)this);
		this.setLayout(thisLayout);
		{
			descriptionScrollPane = new JScrollPane();
			descriptionScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
			descriptionScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
			descriptionScrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
			{
				description = new JEditorPane();
				descriptionScrollPane.setViewportView(description);
				description.setFont(new java.awt.Font("Dialog",2,12));
				description.setBackground(getBackground());
				description.setText(getOption().getDescription());
				description.setEditable(false);
			}
		}
		{
			nameScrollPane = new JScrollPane();
			nameScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
			nameScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
			nameScrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
			{
				name = new JEditorPane();
				nameScrollPane.setViewportView(name);
				name.setBackground(getBackground());
				name.setText(getOption().getName());
				description.setEditable(false);
			}
		}
		{
			valueScrollPane = new JScrollPane();
			{
				value = new JEditorPane();
				valueScrollPane.setViewportView(value);
			}
		}
		thisLayout.setVerticalGroup(thisLayout.createSequentialGroup()
			.addGroup(thisLayout.createParallelGroup()
			    .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
			        .addComponent(valueScrollPane, 0, 145, Short.MAX_VALUE)
			        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
			        .addComponent(descriptionScrollPane, GroupLayout.PREFERRED_SIZE, 14, GroupLayout.PREFERRED_SIZE))
			    .addGroup(thisLayout.createSequentialGroup()
			        .addComponent(nameScrollPane, GroupLayout.PREFERRED_SIZE, 168, GroupLayout.PREFERRED_SIZE)
			        .addGap(0, 0, Short.MAX_VALUE)))
			.addContainerGap());
		thisLayout.setHorizontalGroup(thisLayout.createSequentialGroup()
			.addContainerGap()
			.addComponent(nameScrollPane, GroupLayout.PREFERRED_SIZE, 85, GroupLayout.PREFERRED_SIZE)
			.addGap(18)
			.addGroup(thisLayout.createParallelGroup()
			    .addComponent(valueScrollPane, GroupLayout.Alignment.LEADING, 0, 242, Short.MAX_VALUE)
			    .addComponent(descriptionScrollPane, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 242, GroupLayout.PREFERRED_SIZE))
			.addContainerGap(12, 12));
		value.addFocusListener(new FocusListener() {
			
			@Override
			public void focusLost(FocusEvent e) {
				saveValue();
			}
			
			@Override
			public void focusGained(FocusEvent e) {
				checkValue();
			}
		});
		value.addKeyListener(new KeyListener() {
			
			@Override
			public void keyTyped(KeyEvent e) {
			}
			
			@Override
			public void keyReleased(KeyEvent e) {
				checkValue();
			}
			
			@Override
			public void keyPressed(KeyEvent e) {
			}
		});
		this.setPreferredSize(new java.awt.Dimension(369, 180));
		reloadValue();
	}


	@Override
	public void saveValue() {
		String current = value.getText();
		if(getOption().isValid(current)) {
//			getOption().parseValue(current); // without controller
			getController().setOptionValue(getPlugin(), getOption().getName(), current);
		}
	}

	@Override
	public void checkValue() {
		String current = value.getText();
		if(getOption().isValid(current)) {
			value.setBackground(Colors.DEFAULT);
		}
		else {
			value.setBackground(Colors.INVALID);
		}
	}

	@Override
	public void reloadValue() {
		value.setText(getOption().getValueAsString());
		checkValue();
	}

}
