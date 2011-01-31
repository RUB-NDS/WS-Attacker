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

package wsattacker.gui.component.testsuite;
import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.LayoutStyle;

import wsattacker.main.composition.ControllerInterface;

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
public class WsdlLoaderGUI extends javax.swing.JPanel {
	private final String firstURL = "http://";
	private static final long serialVersionUID = 1L;
	private JTextField uri;
	private JButton loader;
	private JLabel operationLabel;
	private JScrollPane requestScrollPanePlain;
	private RequestInputEditor requestInputEditor;
	private JTabbedPane jTabbedPane1;
	private JLabel serviceLabel;
	private AbstractAction serviceChooseAction;
	private InterfaceComboBox interfaceComboBox;
	private JScrollPane namespaceScrollPane;
	private JScrollPane requestScrollPaneForm;
	private OperationComboBox operationComboBox;
	private JLabel inputLabel;
	private JLabel namespaceLabel;
	private RequestInputTable requestInputTable;
	private NamespaceTable namespaceTable;
	private AbstractAction operationChooseAction;
	private AbstractAction newRequestAction;
	private AbstractAction loaderAction;
	private JButton newRequest;
	private ControllerInterface controller = null;
	
	public WsdlLoaderGUI(ControllerInterface controller) {
		super();
		this.controller = controller;
		setName("WSDL Loader");
		initGUI();
	}
	
	private void initGUI() {
		try {
			GroupLayout thisLayout = new GroupLayout((JComponent)this);
			this.setLayout(thisLayout);
			this.setPreferredSize(new java.awt.Dimension(510, 393));
			{
				newRequest = new JButton();
				newRequest.setText("New");
				newRequest.setAction(getNewRequestAction());
			}
			{
				loader = new JButton();
				loader.setText("Load");
				loader.setAction(getLoaderAction());
			}
			{
				uri = new WsdlInputField();
//				uri.setText("wsdl-files/prim.wsdl");
				uri.setText(firstURL);
			}
				thisLayout.setVerticalGroup(thisLayout.createSequentialGroup()
					.addContainerGap(20, 20)
					.addGroup(thisLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					    .addComponent(loader, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					    .addComponent(uri, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
					.addGroup(thisLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					    .addComponent(getOperationLabel(), GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					    .addComponent(getServiceLabel(), GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
					.addGroup(thisLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					    .addComponent(newRequest, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					    .addComponent(getOperationComboBox(), GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
					    .addComponent(getServiceComboBox(), GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, 20, GroupLayout.PREFERRED_SIZE))
					.addGap(31)
					.addComponent(getNamespaceLabel(), GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
					.addComponent(getJScrollPane1(), GroupLayout.PREFERRED_SIZE, 111, GroupLayout.PREFERRED_SIZE)
					.addComponent(getInputLabel(), GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
					.addComponent(getJTabbedPane1(), 0, 107, Short.MAX_VALUE)
					.addContainerGap());
				thisLayout.setHorizontalGroup(thisLayout.createSequentialGroup()
					.addContainerGap(21, 21)
					.addGroup(thisLayout.createParallelGroup()
					    .addGroup(thisLayout.createSequentialGroup()
					        .addGroup(thisLayout.createParallelGroup()
					            .addComponent(getServiceComboBox(), GroupLayout.Alignment.LEADING, 0, 200, Short.MAX_VALUE)
					            .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
					                .addComponent(getServiceLabel(), GroupLayout.PREFERRED_SIZE, 193, GroupLayout.PREFERRED_SIZE)
					                .addGap(7)))
					        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
					        .addGroup(thisLayout.createParallelGroup()
					            .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
					                .addComponent(getOperationComboBox(), 0, 177, Short.MAX_VALUE)
					                .addGap(20))
					            .addGroup(thisLayout.createSequentialGroup()
					                .addComponent(getOperationLabel(), GroupLayout.PREFERRED_SIZE, 197, GroupLayout.PREFERRED_SIZE)
					                .addGap(0, 0, Short.MAX_VALUE)))
					        .addGap(67))
					    .addGroup(thisLayout.createSequentialGroup()
					        .addGroup(thisLayout.createParallelGroup()
					            .addComponent(uri, GroupLayout.Alignment.LEADING, 0, 392, Short.MAX_VALUE)
					            .addGroup(thisLayout.createSequentialGroup()
					                .addComponent(getNamespaceLabel(), GroupLayout.PREFERRED_SIZE, 392, GroupLayout.PREFERRED_SIZE)
					                .addGap(0, 0, Short.MAX_VALUE))
					            .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
					                .addComponent(getInputLabel(), GroupLayout.PREFERRED_SIZE, 324, GroupLayout.PREFERRED_SIZE)
					                .addGap(0, 68, Short.MAX_VALUE)))
					        .addGap(10)
					        .addGroup(thisLayout.createParallelGroup()
					            .addComponent(newRequest, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 75, GroupLayout.PREFERRED_SIZE)
					            .addComponent(loader, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 75, GroupLayout.PREFERRED_SIZE)))
					    .addComponent(getJScrollPane1(), GroupLayout.Alignment.LEADING, 0, 477, Short.MAX_VALUE)
					    .addComponent(getJTabbedPane1(), GroupLayout.Alignment.LEADING, 0, 477, Short.MAX_VALUE))
					.addContainerGap());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void setController(ControllerInterface controller) {
		this.controller = controller;
	}
	
	public JTextField getUriField() {
		return uri;
	}
	
	public JButton getLoadButton() {
		return loader;
	}
	
	public JButton getNewRequestButtom() {
		return newRequest;
	}
	
	@SuppressWarnings("serial")
	private AbstractAction getLoaderAction() {
		if(loaderAction == null) {
			loaderAction = new AbstractAction("Load", null) {
				public void actionPerformed(ActionEvent evt) {
					controller.setWsdl(uri.getText());
				}
			};
		}
		return loaderAction;
	}
	
	@SuppressWarnings("serial")
	private AbstractAction getNewRequestAction() {
		if(newRequestAction == null) {
			newRequestAction = new AbstractAction("New", null) {
				public void actionPerformed(ActionEvent evt) {
					controller.resetRequestContent();
				}
			};
		}
		return newRequestAction;
	}
	
	@SuppressWarnings("serial")
	private AbstractAction getOperationChooseAction() {
		if(operationChooseAction == null) {
			operationChooseAction = new AbstractAction("Choose Operation", null) {
				public void actionPerformed(ActionEvent evt) {
			        JComboBox cb = (JComboBox)evt.getSource();
			        String operationName = (String) cb.getSelectedItem();
			        controller.setCurrentOperation(operationName);
				}
			};
		}
		return operationChooseAction;
	}
	
	public NamespaceTable getNamespaceTable() {
		if(namespaceTable == null) {
			namespaceTable = new NamespaceTable();
			namespaceTable.setAutoResizeMode(JTable.AUTO_RESIZE_NEXT_COLUMN);
		}
		return namespaceTable;
	}

	public RequestInputTable getRequestInputTable() {
		if(requestInputTable == null) {
			requestInputTable = new RequestInputTable(controller);
		}
		return requestInputTable;
	}
	
	private JLabel getNamespaceLabel() {
		if(namespaceLabel == null) {
			namespaceLabel = new JLabel();
			namespaceLabel.setText("Namespaces:");
		}
		return namespaceLabel;
	}
	
	private JLabel getInputLabel() {
		if(inputLabel == null) {
			inputLabel = new JLabel();
			inputLabel.setText("Input:");
		}
		return inputLabel;
	}
	
	private JScrollPane getJScrollPane1() {
		if(namespaceScrollPane == null) {
			namespaceScrollPane = new JScrollPane();
			namespaceScrollPane.setViewportView(getNamespaceTable());
		}
		return namespaceScrollPane;
	}
	
	private JScrollPane getJScrollPane2() {
		if(requestScrollPaneForm == null) {
			requestScrollPaneForm = new JScrollPane();
			requestScrollPaneForm.setBounds(140, 0, 22, 22);
			requestScrollPaneForm.setViewportView(getRequestInputTable());
		}
		return requestScrollPaneForm;
	}
	
	public OperationComboBox getOperationComboBox() {
		if(operationComboBox == null) {
			operationComboBox = new OperationComboBox();
			operationComboBox.setAction(getOperationChooseAction());
		}
		return operationComboBox;
	}
	
	public InterfaceComboBox getServiceComboBox() {
		if(interfaceComboBox == null) {
			ComboBoxModel serviceComboBoxModel = 
				new DefaultComboBoxModel(
						new String[] { "" });
			interfaceComboBox = new InterfaceComboBox();
			interfaceComboBox.setModel(serviceComboBoxModel);
			interfaceComboBox.setAction(getServiceChooseAction());
		}
		return interfaceComboBox;
	}
	
	@SuppressWarnings("serial")
	private AbstractAction getServiceChooseAction() {
		if(serviceChooseAction == null) {
			serviceChooseAction = new AbstractAction("Choose Service", null) {
				public void actionPerformed(ActionEvent evt) {
					JComboBox cb = (JComboBox)evt.getSource();
			        int index = cb.getSelectedIndex();
			        controller.setCurrentService(index);
				}
			};
		}
		return serviceChooseAction;
	}
	
	private JLabel getServiceLabel() {
		if(serviceLabel == null) {
			serviceLabel = new JLabel();
			serviceLabel.setText("Interface");
		}
		return serviceLabel;
	}
	
	private JLabel getOperationLabel() {
		if(operationLabel == null) {
			operationLabel = new JLabel();
			operationLabel.setText("Operation");
		}
		return operationLabel;
	}
	
	private JTabbedPane getJTabbedPane1() {
		if(jTabbedPane1 == null) {
			jTabbedPane1 = new JTabbedPane();
			jTabbedPane1.addTab("Form View", null, getJScrollPane2(), null);
			jTabbedPane1.addTab("Expert View", null, getJScrollPane1x(), null);
		}
		return jTabbedPane1;
	}
	
	private RequestInputEditor getRequestInputEditor() {
		if(requestInputEditor == null) {
			requestInputEditor = new RequestInputEditor(controller);
		}
		return requestInputEditor;
	}
	
	private JScrollPane getJScrollPane1x() {
		if(requestScrollPanePlain == null) {
			requestScrollPanePlain = new JScrollPane();
			requestScrollPanePlain.setPreferredSize(new java.awt.Dimension(481, 105));
			requestScrollPanePlain.setViewportView(getRequestInputEditor());
		}
		return requestScrollPanePlain;
	}
}
