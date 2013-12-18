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
package wsattacker.gui.component.expertview;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.panels.iface.WsdlInterfacePanelBuilder;
import com.eviware.soapui.impl.wsdl.panels.operation.WsdlOperationPanelBuilder;
import com.eviware.soapui.impl.wsdl.panels.request.WsdlRequestPanelBuilder;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import wsattacker.main.testsuite.CurrentInterface;
import wsattacker.main.testsuite.CurrentOperation;
import wsattacker.main.testsuite.CurrentRequest;
import wsattacker.main.testsuite.TestSuite;

/**
 * This code was edited or generated using CloudGarden's Jigloo SWT/Swing GUI
 * Builder, which is free for non-commercial use. If Jigloo is being used
 * commercially (ie, by a corporation, company or business for any purpose
 * whatever) then you should purchase a license for each developer using Jigloo.
 * Please visit www.cloudgarden.com for details. Use of Jigloo implies
 * acceptance of these licensing terms. A COMMERCIAL LICENSE HAS NOT BEEN
 * PURCHASED FOR THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED LEGALLY FOR
 * ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
public class ExpertView implements PropertyChangeListener {

	Component servicePanel, operationPanel, requestPanel;
	JPanel panel;
	WsdlInterfacePanelBuilder serviceBuilder;
	WsdlOperationPanelBuilder operationBuilder;
	WsdlRequestPanelBuilder requestBuilder;

	public ExpertView(TestSuite testSuite) {
		// panel builders
		serviceBuilder = new WsdlInterfacePanelBuilder();
		operationBuilder = new WsdlOperationPanelBuilder();
		requestBuilder = new WsdlRequestPanelBuilder();

		// returned component
		panel = new JPanel();
		GridBagLayout panelLayout = new GridBagLayout();
		panelLayout.rowWeights = new double[]{0.2, 0.2, 0.6};
		panelLayout.rowHeights = new int[]{99, 98, 7};
		panelLayout.columnWeights = new double[]{0.1};
		panelLayout.columnWidths = new int[]{7};
		panel.setLayout(panelLayout);
		panel.setName("Expert View");
		panel.setPreferredSize(new java.awt.Dimension(368, 374));

		// observe
//		testSuite.getCurrentInterface().addCurrentServiceObserver(this);
//		testSuite.getCurrentOperation().addCurrentOperationObserver(this);
//		testSuite.getCurrentRequest().addCurrentRequestObserver(this);
		testSuite.getCurrentInterface().addPropertyChangeListener(CurrentInterface.PROP_WSDLINTERFACE, this);
		testSuite.getCurrentOperation().addPropertyChangeListener(CurrentOperation.PROP_WSDLOPERATION, this);
		testSuite.getCurrentRequest().addPropertyChangeListener(CurrentRequest.PROP_WSDLREQUEST, this);
	}

	public Component getView() {
		return panel;
	}

	public void currentRequestChanged(WsdlRequest newRequest,
		WsdlRequest oldRequest) {
		if (requestPanel != null && SwingUtilities.isDescendingFrom(requestPanel, panel)) {
			panel.remove(requestPanel);
		}
		requestPanel = requestBuilder.buildOverviewPanel(newRequest); // TODO: This causes an Error with JDK7
//		panel.add(requestPanel,panel.getComponentCount()>1?2:panel.getComponentCount());
		panel.add(requestPanel, new GridBagConstraints(0, 2, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH, new Insets(0, 0, 0, 0), 0, 0));
	}

	public void noCurrentRequest() {
		if (requestPanel != null && SwingUtilities.isDescendingFrom(requestPanel, panel)) {
			panel.remove(requestPanel);
		}
//		requestPanel = null;
	}

	public void currentOperationChanged(WsdlOperation newOperation,
		WsdlOperation oldOperation) {
		if (operationPanel != null && SwingUtilities.isDescendingFrom(operationPanel, panel)) {
			panel.remove(operationPanel);
		}
		operationPanel = operationBuilder.buildOverviewPanel(newOperation);
//		panel.add(operationPanel,panel.getComponentCount()>0?1:panel.getComponentCount());
		panel.add(operationPanel, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH, new Insets(0, 0, 0, 0), 0, 0));
	}

	public void noCurrentOperation() {
		if (operationPanel != null && SwingUtilities.isDescendingFrom(operationPanel, panel)) {
			panel.remove(operationPanel);
		}
//		operationPanel = null;
	}

	public void currentInterfaceChanged(WsdlInterface newService, WsdlInterface oldService) {
		if (servicePanel != null && SwingUtilities.isDescendingFrom(servicePanel, panel)) {
			panel.remove(servicePanel);
		}
		servicePanel = serviceBuilder.buildOverviewPanel(newService);
		panel.add(servicePanel, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH, new Insets(0, 0, 0, 0), 0, 0));
	}

	public void noCurrentInterface() {
		if (servicePanel != null && SwingUtilities.isDescendingFrom(servicePanel, panel)) {
			panel.remove(servicePanel);
		}
//		serviceBuilder = null;
	}

	@Override
	public void propertyChange(PropertyChangeEvent pce) {
		final String propName = pce.getPropertyName();
		if (propName.equals(CurrentRequest.PROP_WSDLREQUEST)) {
			final WsdlRequest newRequest = (WsdlRequest) pce.getNewValue();
			final WsdlRequest oldRequest = (WsdlRequest) pce.getOldValue();
			if (newRequest == null) {
				noCurrentRequest();
			} else {
				currentRequestChanged(newRequest, oldRequest);
			}
		} else if (CurrentInterface.PROP_WSDLINTERFACE.equals(propName)) {
			WsdlInterface newInterface = (WsdlInterface) pce.getNewValue();
			WsdlInterface oldInterface = (WsdlInterface) pce.getOldValue();
			if (newInterface == null) {
				noCurrentInterface();
			} else {
				currentInterfaceChanged(newInterface, oldInterface);
			}
		} else if (CurrentOperation.PROP_WSDLOPERATION.equals(propName)) {
			final WsdlOperation newOperation = (WsdlOperation) pce.getNewValue();
			final WsdlOperation oldOperation = (WsdlOperation) pce.getOldValue();
			currentOperationChanged(newOperation, oldOperation);
		}
	}
}
