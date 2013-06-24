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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.LayoutStyle;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileFilter;

import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.gui.util.Colors;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;

/**
 * This code was edited or generated using CloudGarden's Jigloo SWT/Swing GUI Builder, which is free for non-commercial
 * use. If Jigloo is being used commercially (ie, by a corporation, company or business for any purpose whatever) then
 * you should purchase a license for each developer using Jigloo. Please visit www.cloudgarden.com for details. Use of
 * Jigloo implies acceptance of these licensing terms. A COMMERCIAL LICENSE HAS NOT BEEN PURCHASED FOR THIS MACHINE, SO
 * JIGLOO OR THIS CODE CANNOT BE USED LEGALLY FOR ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
public class OptionSchemaFilesGUI extends AbstractOptionGUI
{
  private static final long serialVersionUID = 1L;
  private JButton           value;
  private JEditorPane       name;
  private JEditorPane       description;
  private AbstractAction    selectFileAction;
  private JLabel            filenameLabel;
  private JScrollPane       descriptionScrollPane;
  private JScrollPane       nameScrollPane;
  private OptionSchemaFiles option;

  private JFileChooser      chooser;

  public OptionSchemaFilesGUI(ControllerInterface controller,
                              AbstractPlugin plugin,
                              OptionSchemaFiles option)
  {
    super(controller, plugin, option);
    this.option = option;
    {
      this.chooser = new JFileChooser();
      chooser.setMultiSelectionEnabled(true);
      this.chooser.setFileFilter(new FileFilter()
      {

        @Override
        public String getDescription()
        {
          return getOptionSchemaFiles().getDescription();
        }

        @Override
        public boolean accept(File f)
        {
          // always show directories
          if (f.isDirectory())
          {
            return true;
          }
          return getOptionSchemaFiles().isValid(f);
        }
      });
    }
    GroupLayout thisLayout = new GroupLayout((JComponent) this);
    this.setLayout(thisLayout);
    {
      value = new JButton();
      value.setText("Browse...");
      value.setAction(getSelectFileAction());
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
      nameScrollPane = new JScrollPane();
      nameScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
      nameScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
      nameScrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
      {
        name = new JEditorPane();
        nameScrollPane.setViewportView(name);
        name.setPreferredSize(new java.awt.Dimension(85, 16));
        name.setBackground(getBackground());
        name.setText(getOption().getName());
        description.setEditable(false);
        description.setPreferredSize(new java.awt.Dimension(242, 54));
      }
    }
    {
      filenameLabel = new JLabel();
      filenameLabel.setText("\"\"");
      filenameLabel.setHorizontalTextPosition(SwingConstants.RIGHT);
    }
    thisLayout.setVerticalGroup(thisLayout.createParallelGroup()
      .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
          .addGroup(thisLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
              .addComponent(filenameLabel, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, 27, GroupLayout.PREFERRED_SIZE)
              .addComponent(value, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
          .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
          .addComponent(descriptionScrollPane, GroupLayout.PREFERRED_SIZE, 54, GroupLayout.PREFERRED_SIZE)
          .addGap(0, 6, Short.MAX_VALUE))
      .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
          .addComponent(nameScrollPane, 0, 87, Short.MAX_VALUE)
          .addGap(6)));
    thisLayout.setHorizontalGroup(thisLayout.createSequentialGroup()
      .addContainerGap()
      .addComponent(nameScrollPane, GroupLayout.PREFERRED_SIZE, 85, GroupLayout.PREFERRED_SIZE)
      .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
      .addGroup(thisLayout.createParallelGroup()
          .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
              .addComponent(filenameLabel, 0, 125, Short.MAX_VALUE)
              .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
              .addComponent(value, GroupLayout.PREFERRED_SIZE, 105, GroupLayout.PREFERRED_SIZE))
          .addComponent(descriptionScrollPane, GroupLayout.Alignment.LEADING, 0, 242, Short.MAX_VALUE))
      .addContainerGap());
    value.addItemListener(new ItemListener()
    {

      @Override
      public void itemStateChanged(ItemEvent arg0)
      {
        saveValue();
      }
    });
    this.setPreferredSize(new java.awt.Dimension(369, 93));
    reloadValue();
  }

  private OptionSchemaFiles getOptionSchemaFiles()
  {
    return option;
  }

  @Override
  public void saveValue()
  {
    File[] selected = chooser.getSelectedFiles();
    checkValue();
    if (option.isValid(selected))
    {
      option.setFiles(selected); // without controller
    }
    String filestring = option.getShortValueAsString();
    if (!filestring.isEmpty()) {
		  description.setText(filestring);
	  }
  }

  @Override
  public void checkValue()
  {
    File selected = chooser.getSelectedFile();
    if (option.isValid(selected))
    {
      value.setBackground(Colors.DEFAULT);
    }
    else
    {
      value.setBackground(Colors.INVALID);
    }
  }

  @Override
  public void reloadValue()
  {
    File selected = chooser.getSelectedFile();
    if (selected != null)
    {
      filenameLabel.setText(selected.getName());
    }
    else
    {
      filenameLabel.setText("");
    }
    checkValue();
    String filestring = option.getShortValueAsString();
    if (!filestring.isEmpty()) {
		  description.setText(filestring);
	  }
  }

  @SuppressWarnings("serial")
  private AbstractAction getSelectFileAction()
  {
    if (selectFileAction == null)
    {
      selectFileAction = new AbstractAction("Browse...", null)
      {
        public void actionPerformed(ActionEvent evt)
        {
          Component c = (Component) evt.getSource();
          Component root = SwingUtilities.getRoot(c);
          chooser.showOpenDialog(root);
          saveValue();
        }
      };
    }
    return selectFileAction;
  }

}
