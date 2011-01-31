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
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.LayoutStyle;
import javax.swing.SwingConstants;

import wsattacker.gui.util.XmlTextPane;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.testsuite.CurrentRequestObserver;

import com.eviware.soapui.impl.wsdl.WsdlRequest;

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
public class RequestResponseGUI extends javax.swing.JPanel implements CurrentRequestObserver {
	private static final long serialVersionUID = 1L;
	private JScrollPane requestScrollPane;
	private JScrollPane responseScrollPane;
	private AbstractAction testRequestAction;
	private JButton testButton;
	private JEditorPane responseContent;
	private JLabel endpointLabel;
	private RequestInputEditor requestContent;
	private JLabel responseLabel;
	private JLabel requestLabel;
	private ControllerInterface controller;
	
	public RequestResponseGUI() {
		super();
	}
	public RequestResponseGUI(ControllerInterface controller) {
		super();
		this.controller = controller;
		setName("Test Request");
		initGUI();
		this.controller.getTestSuite().getCurrentRequest().addCurrentRequestObserver(this);
	}
	
	private void initGUI() {
		try {
			GroupLayout thisLayout = new GroupLayout((JComponent)this);
			this.setLayout(thisLayout);
			this.setPreferredSize(new java.awt.Dimension(431, 355));
			{
				requestLabel = new JLabel();
				requestLabel.setText("Request:");
			}
			{
				responseLabel = new JLabel();
				responseLabel.setText("Response:");
			}
			{
				testButton = new JButton();
				testButton.setText("Test");
				testButton.setAction(getTestRequestAction());
				testButton.setEnabled(false);
			}
			{
				requestScrollPane = new JScrollPane();
				{
					requestContent = new RequestInputEditor(controller);
					requestScrollPane.setViewportView(getRequestContent());
				}
			}
			{
				responseScrollPane = new JScrollPane();
				{
					responseContent = new XmlTextPane();
					responseScrollPane.setViewportView(getResponseContent());
					responseContent.setEditable(false);
					responseContent.setPreferredSize(new java.awt.Dimension(393, 119));
				}
			}
				thisLayout.setVerticalGroup(thisLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(thisLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					    .addComponent(getEndpointLabel(), GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, 14, GroupLayout.PREFERRED_SIZE)
					    .addComponent(requestLabel, GroupLayout.Alignment.BASELINE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
					.addComponent(requestScrollPane, 0, 114, Short.MAX_VALUE)
					.addGap(26)
					.addComponent(responseLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
					.addComponent(responseScrollPane, 0, 118, Short.MAX_VALUE)
					.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
					.addComponent(testButton, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					.addGap(0, 6, GroupLayout.PREFERRED_SIZE));
				thisLayout.setHorizontalGroup(thisLayout.createSequentialGroup()
					.addGap(7)
					.addGroup(thisLayout.createParallelGroup()
					    .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
					        .addComponent(requestLabel, GroupLayout.PREFERRED_SIZE, 117, GroupLayout.PREFERRED_SIZE)
					        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
					        .addGroup(thisLayout.createParallelGroup()
					            .addComponent(getEndpointLabel(), GroupLayout.Alignment.LEADING, 0, 294, Short.MAX_VALUE)
					            .addGroup(GroupLayout.Alignment.LEADING, thisLayout.createSequentialGroup()
					                .addGap(0, 108, Short.MAX_VALUE)
					                .addComponent(testButton, GroupLayout.PREFERRED_SIZE, 186, GroupLayout.PREFERRED_SIZE))))
					    .addComponent(requestScrollPane, GroupLayout.Alignment.LEADING, 0, 417, Short.MAX_VALUE)
					    .addComponent(responseLabel, GroupLayout.Alignment.LEADING, 0, 417, Short.MAX_VALUE)
					    .addComponent(responseScrollPane, GroupLayout.Alignment.LEADING, 0, 417, Short.MAX_VALUE))
					.addGap(7));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public JEditorPane getResponseContent() {
		return responseContent;
	}
	
	public JEditorPane getRequestContent() {
		return requestContent;
	}
	
	@SuppressWarnings("serial")
	private AbstractAction getTestRequestAction() {
		if(testRequestAction == null) {
			testRequestAction = new AbstractAction("Start Test Request", null) {
				public void actionPerformed(ActionEvent evt) {
					controller.doTestRequest();
				}
			};
		}
		return testRequestAction;
	}
	
	private JLabel getEndpointLabel() {
		if(endpointLabel == null) {
			endpointLabel = new JLabel();
			endpointLabel.setText("Endpoint: no current Endpoint");
			endpointLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		}
		return endpointLabel;
	}
	@Override
	public void currentRequestChanged(WsdlRequest newRequest,
			WsdlRequest oldRequest) {
		String endpoint = newRequest.getEndpoint();
		endpointLabel.setText("Endpoint: " + endpoint);
		testButton.setEnabled(true);
		responseContent.setText("");
		
	}
	@Override
	public void noCurrentRequest() {
		endpointLabel.setText("Endpoint: no current Endpoint");
		requestContent.setText("");
		responseContent.setText("");
	}

}
