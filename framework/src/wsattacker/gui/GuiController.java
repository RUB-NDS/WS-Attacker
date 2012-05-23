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

import java.io.File;
import java.io.IOException;
import java.util.Iterator;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import wsattacker.gui.component.log.GuiAppender;
import wsattacker.gui.component.testsuite.RequestResponseGUI;
import wsattacker.gui.component.testsuite.WsdlLoaderGUI;
import wsattacker.main.Preferences;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.plugin.PluginManager;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.testsuite.CurrentRequest;
import wsattacker.main.testsuite.TestSuite;

import com.eviware.soapui.DefaultSoapUICore;
import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.model.iface.Request.SubmitException;

public class GuiController implements ControllerInterface {
	private static GuiController c = new GuiController(); // singleton

	PluginManager pluginManager;
	TestSuite testSuite;
	Preferences prefs;
	Logger log;
	GuiView guiView;

	private boolean abortAttacks;

	Thread runThread;
	PluginRunner runner;

	// singleton
	private GuiController() {
		abortAttacks = false;

		// create a new test suite
		this.testSuite = TestSuite.getInstance();
		// initiate loggers
		initLoggers();
		// get allPlugins
		this.pluginManager = PluginManager.getInstance();
		reloadPlugins();

		// preferences
		this.prefs = Preferences.getInstance();

		// no thread
		this.runThread = new Thread();

		// create gui
		this.guiView = new GuiView(this);
		Thread viewThread = new Thread(this.guiView);
		viewThread.start();
	}

	// singleton
	public static GuiController getInstance() {
		return c;
	}

	private void initLoggers() {
		// Set Logger options
		log = Logger.getRootLogger();
		Logger.getRootLogger().removeAllAppenders();
		PatternLayout layout = new PatternLayout(
				"%d{ABSOLUTE} %-5p [%c{1}] %m%n");
		log.addAppender(new ConsoleAppender(layout));
		log.addAppender(new GuiAppender());
		Logger.getLogger("wstester.util").setLevel(Level.INFO);
		Logger.getLogger("wstester.main.PluginCollection").setLevel(Level.INFO);

		// soapui logger

		Logger.getLogger("com.eviware.soapui").setLevel(Level.OFF);
		Logger.getLogger(DefaultSoapUICore.class).setLevel(Level.OFF);
		Logger.getLogger("com.eviware.soapui.impl").setLevel(Level.OFF);

		// get local logger
		log = Logger.getLogger(getClass());
		log.setLevel(Level.INFO);

	}

	// ==============================================
	// Interface Methods:
	// Plugins
	// ==============================================

	@Override
	public PluginManager getPluginManager() {
		// return this.allPlugins.getPlugins();
		return this.pluginManager;
	}

	@Override
	public void reloadPlugins() {
		log.info("Reloading Plugins");
		getPluginManager().loadAvailablePlugins(new File("plugins"));
	}

	@Override
	public void setPluginActive(int index, boolean active) {
		AbstractPlugin plugin = getPluginManager().getByIndex(index);
		setPluginActive(plugin, active);
	}

	@Override
	public void setPluginActive(String pluginName, boolean active) {
		AbstractPlugin plugin = getPluginManager().getByName(pluginName);
		setPluginActive(plugin, active);
	}

	private void setPluginActive(AbstractPlugin plugin, boolean active) {
		if (plugin != null) {
			if (getPluginManager().isActive(plugin) != active) {
				log.info(String.format((active ? "(+) A" : "(-) Dea")
						+ "ctivating Plugin %s", plugin.getName()));
				getPluginManager().setActive(plugin, active);
			}
		} else {
			log.warn(String.format("(!) Could not activate Plugin"));
		}
	}

	@Override
	public void setAllPluginActive(boolean active) {
		log.info((active ? "(+) A" : "(-) Dea") + "ctivating all Plugins");
		getPluginManager().setAllActive(active);
	}

	@Override
	public boolean setOptionValue(AbstractPlugin plugin, String optionName,
			String optionValue) {
		AbstractOption option = plugin.getPluginOptions().getByName(optionName);
		if (option == null)
			return false;
		if (option.isValid(optionValue)) {
			log.debug(String.format("Set PluginOption for '%s': {%s=%s}",
					plugin.getName(), optionName, optionValue));
			return option.parseValue(optionValue);
		}
		log.debug(String.format("Value {%s=%s} for Plugin '%s' is INVALID!",
				optionName, optionValue, plugin.getName()));
		return false;
	}

	@Override
	public void startActivePlugins() {
		if (runThread.isAlive()) {
			log.fatal("You can't start Attacks. Another process is running.");
			return;
		}
		runner = new PluginRunner(testSuite);
		runThread = new Thread(runner);
		runThread.setName("Run Plugins");
		// SoapUI.getThreadPool().execute(runThread);
		runThread.start();
	}

	public void stopActivePlugins() {
		Thread stopThread = new Thread(new PluginStopper());
		stopThread.run();
	}

	class PluginStopper implements Runnable {
		@SuppressWarnings("deprecation")
		@Override
		public void run() {
			if (runThread.isAlive()
					&& runThread.getName().equals("Run Plugins")) {
				abortAttacks = true;
				log.info("Stopping all active plugins");
				AbstractPlugin active = runner.getActive();
				log.warn("Gently aborting plugin '" + active.getName()
						+ "' (Waiting for 3 sec)");
				active.abortAttack();
				try {
					Thread.sleep(3000);
				} catch (InterruptedException e) {
				} // wait for 3 seconds
					// know force to kill the thread if its still running.
				if (runThread.isAlive()
						&& runThread.getName().equals("Run Plugins")) {
					log.warn("Force to kill thread, since plugin is still running.");
					runThread.stop();
				}
				active.stopAttack();
				Iterator<AbstractPlugin> it = getPluginManager()
						.getActivePluginIterator();
				while (it.hasNext()) {
					AbstractPlugin otherPlugin = it.next();
					if (otherPlugin.isReady()) {
						otherPlugin.stopAttack();
					}
				}
				setEnabledTabs(true, 0, 1, 2);
				abortAttacks = false;
			}
		}
	}

	@Override
	public void cleanPlugins() {
		boolean noError = true;
		Iterator<AbstractPlugin> it = getPluginManager().getPluginIterator();
		AbstractPlugin plugin;
		while (it.hasNext()) {
			plugin = it.next();
			plugin.clean();
			if (plugin.isFinished() || plugin.isRunning()) {
				log.error("Plugin " + plugin.getName()
						+ " could not be cleaned, Status is still "
						+ plugin.getState());
				noError |= false;
			}
			if (plugin.getCurrentPoints() != 0) {
				log.error("Plugin " + plugin.getName()
						+ "could not be cleaned, it has still "
						+ plugin.getCurrentPoints() + " Points");
				noError |= false;
			}
		}
		Result.getGlobalResult().clear();
		if (noError)
			log.info("All Plugins successfully cleaned");
	}

	class PluginRunner implements Runnable {
		TestSuite testSuite;
		AbstractPlugin active;

		public PluginRunner(TestSuite testSuite) {
			this.testSuite = testSuite;
			this.active = null;
		}

		public void run() {
			AbstractPlugin plugin;
			Iterator<AbstractPlugin> it;
			// Check if everything is allright
			if (testSuite.getCurrentRequest().getWsdlRequest() == null) {
				log.warn("You have to load a WSDL first");
				return;
			}
			if (testSuite.getCurrentRequest().getWsdlResponse() == null) {
				log.warn("You must submit a test request first.");
				return;
			}
			if (getPluginManager().countActivePlugins() < 1) {
				log.warn("You must enable at least one Plugin");
				return;
			}
			it = getPluginManager().getActivePluginIterator();
			while (it.hasNext()) {
				plugin = it.next();
				if (!plugin.isReady()) {
					log.warn("Not all Plugins are Ready");
					return;
				}
			}
			// start attack
			log.info("Starting all active Plugins...");
			setEnabledTabs(false, 0, 1, 2);
			it = getPluginManager().getActivePluginIterator();
			while (it.hasNext() && !abortAttacks) {
				plugin = it.next();
				active = plugin;
				log.info("Starting plugin '" + plugin.getName() + "'");
				plugin.startAttack();
				log.info("Plugin finished: " + plugin.getCurrentPoints() + "/"
						+ plugin.getMaxPoints());
			}
			active = null;
			setEnabledTabs(true, 0, 1, 2);
		}

		public AbstractPlugin getActive() {
			return active;
		}
	}

	@Override
	public void savePluginConfiguration(File file) {
		try {
			getPluginManager().savePlugins(file);
		} catch (IOException e) {
			log.error("IO Exception : " + e.getMessage());
		} catch (Exception e) {
			log.error("Unknown Error:" + e.getMessage());
		}
	}

	@Override
	public void loadPluginConfiguration(File file) {
		try {
			getPluginManager().loadPlugins(file);
		} catch (IOException e) {
			log.error("IO Exception : " + e.getMessage());
		} catch (ClassNotFoundException e) {
			log.error("Could not find all Plugin Classes");
		} catch (Exception e) {
			log.error("Unknown Error:" + e.getMessage());
		}
		log.info("Successfully loaded Configuration");
	}

	// ==============================================
	// Interface Methods:
	// WsdlProject
	// ==============================================
	@Override
	public TestSuite getTestSuite() {
		return this.testSuite;
	}

	@Override
	public void setWsdl(String uri) {
		if (runThread.isAlive()) {
			log.fatal("You can't start Attacks. Another process is running.");
			return;
		}
		log.info("Trying to load WSDL from '" + uri + "'");
		Runnable runner = new WsdlLoadRunner(uri);
		runThread = new Thread(runner);
		runThread.setName("Load WSDL");
		runThread.start();
		// SoapUI.getThreadPool().execute(runThread);
	}

	class WsdlLoadRunner implements Runnable {
		String uri;

		public WsdlLoadRunner(String uri) {
			this.uri = uri;
		}

		@Override
		public void run() {
			WsdlLoaderGUI wsdlGui = guiView.getWsdlLoader();

			// disable fields
			wsdlGui.getUriField().setEnabled(false);
			wsdlGui.getLoadButton().setEnabled(false);
			wsdlGui.getServiceComboBox().setEnabled(false);
			wsdlGui.getOperationComboBox().setEnabled(false);
			wsdlGui.getNewRequestButtom().setEnabled(false);
			wsdlGui.updateUI();

			try {
				testSuite.setWsdl(uri);
				// re-enable fields
				wsdlGui.getServiceComboBox().setEnabled(true);
				wsdlGui.getOperationComboBox().setEnabled(true);
				wsdlGui.getNewRequestButtom().setEnabled(true);
			} catch (Exception e) {
				e.printStackTrace();
				log.error("Wsdl File could not be loaded: " + e.getMessage());
			} finally {
				// re-enable fields
				wsdlGui.getUriField().setEnabled(true);
				wsdlGui.getLoadButton().setEnabled(true);
			}
		}
	}

	@Override
	public boolean setCurrentService(String serviceName) {
		WsdlProject project = testSuite.getProject();
		if ((project != null)
				&& (project.getInterfaceByName(serviceName) != null)) {
			WsdlInterface service = (WsdlInterface) project
					.getInterfaceByName(serviceName);
			setCurrentService(service);
			return true;
		} else {
			log.warn("No such service available");
			return false;
		}

	}

	@Override
	public boolean setCurrentService(int index) {
		WsdlProject project = testSuite.getProject();
		if ((project != null) && (index >= 0)
				&& (index < project.getInterfaceCount())) {
			WsdlInterface service = (WsdlInterface) project
					.getInterfaceAt(index);
			setCurrentService(service);
			return true;
		} else {
			log.warn("No such service available");
			return false;
		}
	}

	private void setCurrentService(WsdlInterface service) {
		this.testSuite.getCurrentService().setWsdlService(service);
		log.info("Set current service to '" + service.getName() + "'");
	}

	@Override
	public boolean setCurrentOperation(String operationString) {
		WsdlOperation operation = testSuite.getCurrentService()
				.getWsdlService().getOperationByName(operationString);
		return setCurrentOperation(operation);
	}

	@Override
	public boolean setCurrentOperation(int index) {
		WsdlOperation operation = testSuite.getCurrentService()
				.getWsdlService().getOperationAt(index);
		return setCurrentOperation(operation);

	}

	private boolean setCurrentOperation(WsdlOperation operation) {
		if (operation == null) {
			log.warn("Unset current operatoin (null)");
			return false;
		}
		this.testSuite.getCurrentOperation().setWsdlOperation(operation);
		log.info("Set current operation to '" + operation.getName() + "'");
		return true;
	}

	@Override
	public void resetRequestContent() {
		WsdlRequest request = testSuite.getCurrentRequest().getWsdlRequest();
		if (request != null) {
			log.info("Resetting content for basic Request");
			request.setRequestContent(request.getOperation().createRequest(
					prefs.isCreateOtionalElements()));
		}
	}

	@Override
	public void setRequestContent(String content) {
		log.trace("Setting request content to:\n" + content);
		WsdlRequest request = testSuite.getCurrentRequest().getWsdlRequest();
		if (request != null) {
			request.setRequestContent(content);
		} else {
			log.warn("There is no current Request");
		}
	}

	@Override
	public void doTestRequest() {
		if (runThread.isAlive()) {
			log.fatal("You can't do a Test Request. Another process is running.");
		}
		WsdlRequest request = testSuite.getCurrentRequest().getWsdlRequest();
		if (request == null) {
			log.warn("You have to load a WSDL first");
			return;
		}
		log.info("Doing a Test Request");
		Runnable runner = new TestRequest(testSuite.getCurrentRequest());
		runThread = new Thread(runner);
		runThread.setName("Test Request");
		runThread.start();
		// SoapUI.getThreadPool().execute(runThread);

	}

	class TestRequest implements Runnable {
		CurrentRequest request;

		public TestRequest(CurrentRequest request) {
			this.request = request;
		}

		@Override
		public void run() {
			RequestResponseGUI gui = guiView.getTestRequest();
			gui.getResponseContent().setText("Submitting Request...");
			log.info("Submitting Request...");
			try {
				request.submitRequest();
			} catch (NullPointerException e) {
				String error = "Error while doing Test Request"
						+ e.getMessage();
				log.error(error);
				gui.getResponseContent().setText(error);
				e.printStackTrace();
				return;
			} catch (SubmitException e) {
				String error = "Error while doing Test Request. "
						+ e.getMessage();
				log.error(error);
				gui.getResponseContent().setText(error);
				e.printStackTrace();
				return;
			} catch (Exception e) {
				log.error("Unknown Error:" + e.getMessage());
				return;
			}
			String responseContent = request.getWsdlResponse()
					.getContentAsString();
			if (responseContent == null) {
				log.warn("Got an empty response. Bad request?");
				gui.getResponseContent().setText("");
			} else {
				log.info("Successfully received Response");
				gui.getResponseContent().setText(
						(responseContent == null) ? "" : responseContent);
			}
		}
	}

	// ==============================================
	// Help Methods:
	// ==============================================
	private void setEnabledTabs(boolean enabled, int... tabindex) {
		for (int i : tabindex) {
			guiView.getMainWindows().getTabs().setEnabledAt(i, enabled);
		}
	}
	
	// Additional Getter

	public GuiView getGuiView() {
		return guiView;
	}
}
