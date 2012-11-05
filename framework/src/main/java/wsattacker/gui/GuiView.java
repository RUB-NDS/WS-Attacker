/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010 Christian Mainka
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
package wsattacker.gui;

import com.eviware.x.form.XFormFactory;
import com.eviware.x.impl.swing.SwingFormFactory;
import javax.swing.WindowConstants;
import wsattacker.gui.component.MainWindow;
import wsattacker.gui.component.attackoverview.AttackOverview_NB;
import wsattacker.gui.component.expertview.ExpertView;
import wsattacker.gui.component.log.GuiAppender;
import wsattacker.gui.component.pluginconfiguration.PluginConfigurationGUI;
import wsattacker.gui.component.target.WsdlLoaderGUI_NB;
import wsattacker.gui.component.testrequest.RequestResponseGUI;
import wsattacker.main.composition.ControllerInterface;

public class GuiView implements Runnable {
	ControllerInterface controller;
	WsdlLoaderGUI_NB wsdlLoader;
	MainWindow mainWindow;
	PluginConfigurationGUI pluginConfig;
	AttackOverview_NB attack;
	RequestResponseGUI testRequest;

	ExpertView expertView;

	GuiView(ControllerInterface controller) {
		this.controller = controller;
	}

	public void createView() {
		mainWindow = new MainWindow();

		// WsdlLoader
		wsdlLoader = new WsdlLoaderGUI_NB();
		wsdlLoader.setController(controller);

		mainWindow.getTabs().add(wsdlLoader);

		// Test Request
		testRequest = new RequestResponseGUI(controller);
		mainWindow.getTabs().add(testRequest);

		// plugin config
		pluginConfig = new PluginConfigurationGUI(controller);
		mainWindow.getTabs().add(pluginConfig);

		// attack
		attack = new AttackOverview_NB(controller);
		mainWindow.getTabs().add(attack);

		// log
		mainWindow.getTabs().add(GuiAppender.getLog());

		// etc
		mainWindow.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		mainWindow.pack();
		mainWindow.setVisible(true);

		// expert view
		expertView = new ExpertView(controller.getTestSuite());
		mainWindow.getTabs().add(expertView.getView());

		// this will be needed for some soapui dialogs, e.g. basic authentication
		XFormFactory.Factory.instance = new SwingFormFactory();
	}

	public WsdlLoaderGUI_NB getWsdlLoader() {
		return wsdlLoader;
	}

	public MainWindow getMainWindows() {
		return mainWindow;
	}

	public RequestResponseGUI getTestRequest() {
		return testRequest;
	}

        public AttackOverview_NB getAttackOverview() {
                return attack;
        }

	@Override
	public void run() {
		createView();
	}
}
