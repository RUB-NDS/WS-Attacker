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

package wsattacker.gui;

import javax.swing.WindowConstants;

import com.eviware.x.form.XFormFactory;
import com.eviware.x.impl.swing.SwingFormFactory;

import wsattacker.gui.component.MainWindow;
import wsattacker.gui.component.log.GuiAppender;
import wsattacker.gui.component.plugin.AttackOverview;
import wsattacker.gui.component.plugin.PluginConfigurationGUI;
import wsattacker.gui.component.testsuite.ExpertView;
import wsattacker.gui.component.testsuite.RequestResponseGUI;
import wsattacker.gui.component.testsuite.WsdlLoaderGUI;
import wsattacker.main.composition.ControllerInterface;

public class GuiView implements Runnable {
	ControllerInterface controller;
	WsdlLoaderGUI wsdlLoader;
	MainWindow mainWindow;
	PluginConfigurationGUI pluginConfig;
	AttackOverview attack;
	RequestResponseGUI testRequest;
	
	ExpertView expertView;

	GuiView(ControllerInterface controller) {
		this.controller = controller;
	}

	public void createView() {
		mainWindow = new MainWindow();
		
		// WsdlLoader
		wsdlLoader = new WsdlLoaderGUI(controller);
		mainWindow.getTabs().add(wsdlLoader);
		
		// Test Request
		testRequest = new RequestResponseGUI(controller);
		mainWindow.getTabs().add(testRequest);
		
		// plugin config
		pluginConfig = new PluginConfigurationGUI(controller);
		mainWindow.getTabs().add(pluginConfig);
		
		// attack
		attack = new AttackOverview(controller);
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
	
	public WsdlLoaderGUI getWsdlLoader() {
		return wsdlLoader;
	}
	
	public MainWindow getMainWindows() {
		return mainWindow;
	}
	
	public RequestResponseGUI getTestRequest() {
		return testRequest;
	}

	@Override
	public void run() {
		createView();
	}
}
