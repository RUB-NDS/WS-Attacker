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

import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.panels.iface.WsdlInterfacePanelBuilder;
import com.eviware.soapui.impl.wsdl.panels.operation.WsdlOperationPanelBuilder;
import com.eviware.soapui.impl.wsdl.panels.request.WsdlRequestPanelBuilder;
import com.eviware.soapui.model.workspace.Workspace;
import com.eviware.soapui.ui.Navigator;
import java.awt.Component;
import javax.swing.JPanel;
import wsattacker.main.testsuite.TestSuite;

// TODO: Idea for a "better" Expert view
public class ExpertViewSoapUITree {
	Component servicePanel, operationPanel, requestPanel;
	JPanel panel;
	WsdlInterfacePanelBuilder serviceBuilder;
	WsdlOperationPanelBuilder operationBuilder;
	WsdlRequestPanelBuilder requestBuilder;

	public ExpertViewSoapUITree(TestSuite testSuite) {
		// returned component
		WsdlProject project = testSuite.getProject();
		Workspace workspace = project.getWorkspace();
		panel = new Navigator(workspace);
		panel.setName("Expert View");
		panel.setPreferredSize(new java.awt.Dimension(368, 374));
	}

	public Component getView() {
		return panel;
	}

}
