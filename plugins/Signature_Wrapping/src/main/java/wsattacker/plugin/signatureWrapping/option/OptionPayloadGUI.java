/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2011 Christian Mainka
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
package wsattacker.plugin.signatureWrapping.option;

import java.awt.Color;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.InputVerifier;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.LayoutStyle;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.gui.util.Colors;
import wsattacker.gui.util.XmlTextPane;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;

/**
 * This code was edited or generated using CloudGarden's Jigloo SWT/Swing GUI Builder, which is free for non-commercial
 * use. If Jigloo is being used commercially (ie, by a corporation, company or business for any purpose whatever) then
 * you should purchase a license for each developer using Jigloo. Please visit www.cloudgarden.com for details. Use of
 * Jigloo implies acceptance of these licensing terms. A COMMERCIAL LICENSE HAS NOT BEEN PURCHASED FOR THIS MACHINE, SO
 * JIGLOO OR THIS CODE CANNOT BE USED LEGALLY FOR ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
public class OptionPayloadGUI extends AbstractOptionGUI
{
  private static final long serialVersionUID = 1L;
  private JEditorPane       value;
  private JCheckBox         isTimestampCheckBox;
  private JTextField workingXPath;
  private JLabel workingXPathLabel;
  private JLabel            isTimestampLabel;
  private JEditorPane       name;
  private JEditorPane       description;
  private JScrollPane       valueScrollPane;
  private JScrollPane       descriptionScrollPane;
  private JScrollPane       nameScrollPane;
  private OptionPayload     optionPayload;

  public OptionPayloadGUI(ControllerInterface controller,
                          AbstractPlugin plugin,
                          AbstractOption option)
  {
    super(controller, plugin, option);
    this.optionPayload = (OptionPayload) option;
    GroupLayout thisLayout = new GroupLayout((JComponent) this);
    this.setLayout(thisLayout);
    {
      valueScrollPane = new JScrollPane();
      {
        // Payload
        value = new XmlTextPane();
        valueScrollPane.setViewportView(value);
        valueScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        valueScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        value.setInputVerifier(new InputVerifier()
        {

          @Override
          public boolean verify(JComponent arg0)
          {
// if (((OptionPayload)getOption()).isTimestamp()) {
// setEditable(false);
// return false;
// }
            String current = value.getText();
            boolean ok = getOption().isValid(current);
            if (ok)
            {
              value.setBackground(Colors.DEFAULT);
              getController().setOptionValue(getPlugin(), getOption().getName(), current);
            }
            else
              value.setBackground(Colors.INVALID);
            return ok;
          }
        });
        value.setPreferredSize(new java.awt.Dimension(239, 47));
      }
      // isTimestamp Checkbox
      isTimestampCheckBox = new JCheckBox();
      {
        isTimestampCheckBox.setSelected(optionPayload.isTimestamp());
        isTimestampCheckBox.setBackground(getBackground());
        isTimestampCheckBox.addItemListener(new ItemListener()
        {

          @Override
          public void itemStateChanged(ItemEvent ie)
          {
            boolean isT = isTimestampCheckBox.isSelected();
            ((OptionPayload) getOption()).setTimestamp(isT);
            setEditable(!isT);
          }
        });
      }
      isTimestampLabel = new JLabel();
      {
        isTimestampLabel.setText("Timestamp?");
      }

    }
    {
      descriptionScrollPane = new JScrollPane();
      descriptionScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
      descriptionScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
      descriptionScrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
      {
        description = new JEditorPane();
        descriptionScrollPane.setViewportView(description);
        description.setFont(new java.awt.Font("Dialog", 2, 12));
        description.setBackground(getBackground());
        description.setText(getOption().getDescription());
        description.setEditable(false);
      }
    }
    {
      workingXPathLabel = new JLabel();
      workingXPathLabel.setText("Analyzing:");
    }
    {
      workingXPath = new JTextField();
      workingXPath.setText(optionPayload.getReferringElement().getXPath());
      workingXPath.getDocument().addDocumentListener(new DocumentListener()
      {
        
        @Override
        public void removeUpdate(DocumentEvent arg0)
        {
          optionPayload.getReferringElement().setXPath(workingXPath.getText());
        }
        
        @Override
        public void insertUpdate(DocumentEvent arg0)
        {
          optionPayload.getReferringElement().setXPath(workingXPath.getText());
        }
        
        @Override
        public void changedUpdate(DocumentEvent arg0)
        {
          optionPayload.getReferringElement().setXPath(workingXPath.getText());          
        }
      });
    }
    {
      nameScrollPane = new JScrollPane();
      nameScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
      nameScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
      nameScrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
      {
        name = new JEditorPane();
        nameScrollPane.setViewportView(name);
        name.setPreferredSize(new java.awt.Dimension(86, 106));
        name.setBackground(getBackground());
        // Better readability:
        name.setText(getOption().getName().substring(0, getOption().getName().indexOf(':')).replace(' ', '\n'));
        description.setEditable(false);
      }
    }
    thisLayout.setVerticalGroup(thisLayout.createSequentialGroup()
      .addGroup(thisLayout.createParallelGroup()
          .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
              .addComponent(nameScrollPane, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE)
              .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
              .addComponent(isTimestampLabel, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
              .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
              .addComponent(isTimestampCheckBox, GroupLayout.PREFERRED_SIZE, 14, GroupLayout.PREFERRED_SIZE)
              .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
              .addComponent(descriptionScrollPane, GroupLayout.PREFERRED_SIZE, 60, GroupLayout.PREFERRED_SIZE))
          .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
              .addComponent(valueScrollPane, GroupLayout.PREFERRED_SIZE, 160, GroupLayout.PREFERRED_SIZE)
              .addGap(6)))
      .addGroup(thisLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
          .addComponent(workingXPath, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, 22, GroupLayout.PREFERRED_SIZE)
          .addComponent(workingXPathLabel, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
      .addContainerGap());
    thisLayout.setHorizontalGroup(thisLayout.createSequentialGroup()
      .addContainerGap()
      .addGroup(thisLayout.createParallelGroup()
          .addComponent(workingXPathLabel, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 97, GroupLayout.PREFERRED_SIZE)
          .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
              .addComponent(nameScrollPane, GroupLayout.PREFERRED_SIZE, 86, GroupLayout.PREFERRED_SIZE)
              .addGap(11))
          .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
              .addComponent(isTimestampLabel, GroupLayout.PREFERRED_SIZE, 86, GroupLayout.PREFERRED_SIZE)
              .addGap(11))
          .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
              .addComponent(isTimestampCheckBox, GroupLayout.PREFERRED_SIZE, 86, GroupLayout.PREFERRED_SIZE)
              .addGap(11))
          .addComponent(descriptionScrollPane, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 95, GroupLayout.PREFERRED_SIZE))
      .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
      .addGroup(thisLayout.createParallelGroup()
          .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
              .addComponent(workingXPath, 0, 236, Short.MAX_VALUE)
              .addGap(6))
          .addComponent(valueScrollPane, GroupLayout.Alignment.LEADING, 0, 250, Short.MAX_VALUE))
      .addGap(6));
    this.setPreferredSize(new java.awt.Dimension(369, 200));
    reloadValue();
  }

  @Override
  public void saveValue()
  {
    String current = value.getText();
    if (getOption().isValid(current))
    {
      getOption().parseValue(current); // without controller
      getController().setOptionValue(getPlugin(), getOption().getName(), current);
    }
    ((OptionPayload) getOption()).setTimestamp(isTimestampCheckBox.isSelected());
  }

  @Override
  public void checkValue()
  {
    String current = value.getText();
    if (getOption().isValid(current))
    {
      if (value.isEditable()) {
		    value.setBackground(Colors.DEFAULT);
	    }
    }
    else
    {
      value.setBackground(Colors.INVALID);
    }
  }

  @Override
  public void reloadValue()
  {
    value.setText(getOption().getValueAsString());
    setEditable(!(((OptionPayload) getOption()).isTimestamp()));
    checkValue();
  }

  private void setEditable(boolean editable)
  {
    value.setEditable(editable);
    if (editable)
      value.setBackground(Colors.DEFAULT);
    else
      value.setBackground(new Color(0xEFEFEF));
  }
  
  public JLabel getWorkingXPathLabel() {
    return workingXPathLabel;
  }
  
  public JTextField getWorkingXPath() {
    return workingXPath;
  }

}
