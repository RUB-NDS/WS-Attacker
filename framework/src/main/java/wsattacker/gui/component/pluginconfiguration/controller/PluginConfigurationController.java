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
package wsattacker.gui.component.pluginconfiguration.controller;

import java.io.Serializable;
import org.jdesktop.beans.AbstractBean;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.plugin.PluginManager;

public class PluginConfigurationController extends AbstractBean implements Serializable {

	public static final String PROP_PLUGINMANAGER = "pluginManager";
	private PluginManager pluginManager = PluginManager.getInstance();
	private ControllerInterface controller;
	public static final String PROP_CONTROLLER = "controller";

	/**
	 * Get the value of controller
	 *
	 * @return the value of controller
	 */
	public ControllerInterface getController() {
		return controller;
	}

	/**
	 * Set the value of controller
	 *
	 * @param controller new value of controller
	 */
	public void setController(ControllerInterface controller) {
		ControllerInterface oldController = this.controller;
		this.controller = controller;
		firePropertyChange(PROP_CONTROLLER, oldController, controller);
	}

	public PluginConfigurationController() {
	}

	/**
	 * Get the value of pluginManager
	 *
	 * @return the value of pluginManager
	 */
	public PluginManager getPluginManager() {
		return pluginManager;
	}

	/**
	 * Set the value of pluginManager
	 *
	 * @param pluginManager new value of pluginManager
	 */
	public void setPluginManager(PluginManager pluginManager) {
		PluginManager oldPluginManager = this.pluginManager;
		this.pluginManager = pluginManager;
		firePropertyChange(PROP_PLUGINMANAGER, oldPluginManager, pluginManager);
	}
}
