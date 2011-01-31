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

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JScrollPane;
import javax.swing.LayoutStyle;

import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.gui.util.Colors;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOptionBoolean;


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
public class OptionBooleanGUI extends AbstractOptionGUI {
	private static final long serialVersionUID = 1L;
	private JCheckBox value;
	private JEditorPane name;
	private JEditorPane description;
	private JScrollPane descriptionScrollPane;
	private JScrollPane nameScrollPane;
	private AbstractOptionBoolean option;

	public OptionBooleanGUI(ControllerInterface controller, AbstractPlugin plugin, AbstractOptionBoolean option) {
		super(controller, plugin, option);
		this.option = option;
		GroupLayout thisLayout = new GroupLayout((JComponent)this);
		this.setLayout(thisLayout);
		{
			value = new JCheckBox();
			value.setBackground(getBackground());
		}
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
				name.setPreferredSize(new java.awt.Dimension(85, 21));
				name.setBackground(getBackground());
				name.setText(getOption().getName());
				description.setEditable(false);
			}
		}
		thisLayout.setVerticalGroup(thisLayout.createSequentialGroup()
			.addGroup(thisLayout.createParallelGroup()
			    .addGroup(thisLayout.createSequentialGroup()
			        .addComponent(value, GroupLayout.PREFERRED_SIZE, 17, GroupLayout.PREFERRED_SIZE))
			    .addGroup(thisLayout.createSequentialGroup()
			        .addComponent(nameScrollPane, GroupLayout.PREFERRED_SIZE, 17, GroupLayout.PREFERRED_SIZE))
			    .addGroup(thisLayout.createSequentialGroup()
			        .addComponent(descriptionScrollPane, GroupLayout.PREFERRED_SIZE, 17, GroupLayout.PREFERRED_SIZE)))
			.addContainerGap(12, Short.MAX_VALUE));
		thisLayout.setHorizontalGroup(thisLayout.createSequentialGroup()
			.addContainerGap()
			.addComponent(nameScrollPane, GroupLayout.PREFERRED_SIZE, 85, GroupLayout.PREFERRED_SIZE)
			.addGap(17)
			.addComponent(value, GroupLayout.PREFERRED_SIZE, 19, GroupLayout.PREFERRED_SIZE)
			.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
			.addComponent(descriptionScrollPane, 0, 213, Short.MAX_VALUE)
			.addContainerGap());
		value.addItemListener(new ItemListener() {
			
			@Override
			public void itemStateChanged(ItemEvent arg0) {
				saveValue();
			}
		});
		this.setPreferredSize(new java.awt.Dimension(369, 23));
		reloadValue();
	}


	@Override
	public void saveValue() {
		boolean on = value.isSelected();
		if(option.isValid(on)) {
//			option.setOn(on); // without controller
			getController().setOptionValue(getPlugin(), getOption().getName(), (new Boolean(on)).toString());
		}
	}

	@Override
	public void checkValue() {
		boolean on = value.isSelected();
		if(option.isValid(on)) {
			value.setBackground(getBackground());
		}
		else {
			value.setBackground(Colors.INVALID);
		}
	}

	@Override
	public void reloadValue() {
		boolean on = this.option.isOn();
		value.setSelected(on);
		checkValue();
	}

}
