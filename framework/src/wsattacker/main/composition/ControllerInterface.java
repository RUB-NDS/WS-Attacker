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

package wsattacker.main.composition;

import java.io.File;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.plugin.PluginManager;
import wsattacker.main.testsuite.TestSuite;

/**
 * The controller interface
 * @author Christian Mainka
 *
 */
public interface ControllerInterface {
	public PluginManager getPluginManager();

	public void reloadPlugins();

	public void setPluginActive(String pluginName, boolean active);
	public void setPluginActive(int index, boolean active);
	public void setAllPluginActive(boolean active);

	public boolean setOptionValue(AbstractPlugin plugin, String optionName, String optionValue);

	public void startActivePlugins();
	public void stopActivePlugins();
	public void cleanPlugins();

	public TestSuite getTestSuite();

	public void setWsdl(String uri);
	public boolean setCurrentService(int index);
	public boolean setCurrentService(String name);
	public boolean setCurrentOperation(String operationString);
	public boolean setCurrentOperation(int index);
	public void resetRequestContent();
	public void setRequestContent(String content);
	
	public void doTestRequest();
	
	public void savePluginConfiguration(File file);
	public void loadPluginConfiguration(File file);
}
