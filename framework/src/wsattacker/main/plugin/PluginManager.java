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

package wsattacker.main.plugin;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import org.apache.log4j.Logger;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginManagerListener;
import wsattacker.main.composition.plugin.PluginObserver;

import com.eviware.soapui.support.ClasspathHacker;

/**
 * The plugin manger manges all plugins. It can load them, activate them
 * and is observerable.
 * @author Christian Mainka
 *
 */
public class PluginManager implements PluginObserver {
	private static Logger log = Logger.getLogger(PluginManager.class);
	// singleton
	private static PluginManager singleton = new PluginManager();
	PluginContainer allPlugins, activePlugins;

	transient private List<PluginManagerListener> listeners;
	
	private PluginManager()
	{
		// we handle two containers
		allPlugins = new PluginContainer(); // one for ALL available plugins
		activePlugins = new PluginContainer(); // one for active plugins
		listeners = new ArrayList<PluginManagerListener>(); // observers
	}
	
	// singleton
	public static PluginManager getInstance() {
		return singleton;
	}

	/***
	 * Loads all plugins from pluginDir, that means
	 * - add all containing jars to the classpath
	 * - add each available plugin to the list of available plugins
	 * @param pluginDir
	 */
	public void loadAvailablePlugins(File pluginDir) {
		Logger logger = Logger.getLogger(getClass());
		// first we clear all known plugins
		removeAllPlugins();
		logger.info("(Re-)laoding available Plugins");
		log.info("Searching for Plugins in Directory: " + pluginDir.getAbsolutePath());
		if (pluginDir.exists() && pluginDir.isDirectory()) {
			// search in all files
			for(File file : pluginDir.listFiles()) {
				// filter jar files
				if(file.isFile() && file.getName().toLowerCase().endsWith("jar")) {
					try {
						// add to classpath
						ClasspathHacker.addFile(file);
					} catch (IOException e) {
						log.warn("Could not load Plugin " + file);
					}
				}
			}
		}
		
		// add to list of available plugins
		ServiceLoader<AbstractPlugin>  loader = ServiceLoader.load(AbstractPlugin.class);
		
		int anz=0; int suc=0;
		Iterator<AbstractPlugin> it = loader.iterator();
		while(it.hasNext()) {
			++anz;
			Object o = null;
			try {
				o = it.next();
			} catch (ServiceConfigurationError sce) {
				log.error(sce.getMessage());
				continue;
			}
			AbstractPlugin p = (AbstractPlugin) o;
			p.initializePlugin();
			addPlugin(p);
			logger.trace("Loaded Plugin '" + p.getName() + "'");
			++suc;
		}
		String loaded = String.format("Successfuly loaded %d of %d plugins",suc,anz);
		if(suc < anz) {
			log.warn(loaded);
		}
		else {
			log.info(loaded);
		}		
		notifyContainerChanged();
	}
	
	/***
	 * Saves the plugin configuration to a file
	 * @param file
	 * @throws IOException
	 */
	public void savePlugins(File file) throws IOException {
		// create list of active plugins names
		List<String> activeList = new ArrayList<String>();
		for(AbstractPlugin plugin : activePlugins) {
			activeList.add(plugin.getName());
		}
		FileOutputStream fs = new FileOutputStream(file);
		ObjectOutputStream os = new ObjectOutputStream(fs);
		os.writeObject(allPlugins); // save plugin configuration
		os.writeObject(activeList); // save list of active plugins
		os.close();
	}
	
	/***
	 * Loads a plugin configuration from a file
	 * @param file
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public void loadPlugins(File file) throws IOException, ClassNotFoundException {
		Object pluginObject, activeListObject;
		FileInputStream fis;
		ObjectInputStream ois;
		fis = new FileInputStream(file);
		ois = new ObjectInputStream(fis);
		pluginObject = ois.readObject();
		activeListObject = ois.readObject();
		ois.close();
		if (! (pluginObject instanceof PluginContainer)) {
			log.error("Incompatible Filetype. Could not read plugin configuration.");
			return;
		}
		// restore plugin configuration
		PluginContainer collection = (PluginContainer) pluginObject;
		for(AbstractPlugin savedPlugin : collection) {
			AbstractPlugin currentPlugin = allPlugins.getByName(savedPlugin.getName()); // get corresponding plugin
			if(currentPlugin != null) {
				currentPlugin.restoreConfiguration(savedPlugin); // let the plugin restore its config
			} else {
				log.warn("Could not restore Plugin-Configuration for Plugin '" + savedPlugin.getName() + "' - Plugin not available!");
			}
		}
		if (! (activeListObject instanceof List)) {
			log.error("Incompatible Filetype. Could not read active plugin list.");
			return;
		}
		@SuppressWarnings("rawtypes")
		List activeList = (List) activeListObject;
		for(Object active : activeList) {
			if (active instanceof String) {
				// restore plugin active state
				setActive(getByName((String) active), true);
			}
		}
	}
	
	// adding and removing
	
	/**
	 * Remove all available plugins
	 */
	public void removeAllPlugins() {
		for(AbstractPlugin plugin : allPlugins)
			removePlugin(plugin);
	}
	
	/**
	 * Remove plugin from available list
	 * @param plugin
	 */
	public void removePlugin(AbstractPlugin plugin) {
		plugin.removePluginObserver(this);
		activePlugins.remove(plugin);
		allPlugins.remove(plugin);
	}
	
	/**
	 * Add plugin to available list
	 * Can be used for plugin development (no need to generate jar)
	 * @param plugin
	 */
	public void addPlugin(AbstractPlugin plugin) {
		plugin.addPluginObserver(this);
		allPlugins.add(plugin);
	}
	
	/**
	 * Is the plugin active
	 * @param plugin
	 * @return is plugin active
	 */
	public boolean isActive(AbstractPlugin plugin) {
		return activePlugins.contains(plugin);
	}
	
	/**
	 * Sets a plugin active state
	 * @param plugin
	 * @param active
	 */
	public void setActive(AbstractPlugin plugin, boolean active) {
		if(active) {
			activePlugins.add(plugin);
		}
		else {
			activePlugins.remove(plugin);
		}
		notifyActiveChanged(plugin, active);
	}

	public void setAllActive(boolean active) {
		for(AbstractPlugin plugin : allPlugins) {
			setActive(plugin, active);
		}
	}
	
	// accessing plugins
	
	public Iterator<AbstractPlugin> getPluginIterator() {
		return allPlugins.iterator();
	}
	
	public Iterator<AbstractPlugin> getActivePluginIterator() {
		return activePlugins.iterator();
	}
	
	public AbstractPlugin getByName(String pluginName) {
		return allPlugins.getByName(pluginName);
	}
	
	public AbstractPlugin getByIndex(int index) {
		return allPlugins.getByIndex(index);
	}
	
	public AbstractPlugin getActive(int index) {
		return activePlugins.getByIndex(index);
	}
	
	public int indexOf(AbstractPlugin plugin) {
		return allPlugins.indexOf(plugin);
	}
	
	public int indexOfActive(AbstractPlugin plugin) {
		return activePlugins.indexOf(plugin);
	}
	
	// plugin info
	
	public int countPlugins() {
		return allPlugins.size();
	}
	
	public int countActivePlugins() {
		return activePlugins.size();
	}
	
	// Listeners
	
	public void addListener(PluginManagerListener o) {
		listeners.add(o);
	}

	public void removeListener(PluginManagerListener o) {
		listeners.remove(o);
	}
	
	private void notifyActiveChanged(AbstractPlugin plugin, boolean active) {
		for (PluginManagerListener o : listeners) {
			o.pluginActiveStateChanged(plugin, active);
		}
	}

	private void notifyContainerChanged() {
		for (PluginManagerListener o : listeners) {
			o.pluginContainerChanged();
		}
	}

	@Override
	public void currentPointsChanged(AbstractPlugin plugin, int newPoints) {
		for(PluginObserver o : listeners) {
			o.currentPointsChanged(plugin, newPoints);
		}
		
	}

	@Override
	public void pluginStateChanged(AbstractPlugin plugin, PluginState newState,
			PluginState oldState) {
		for(PluginObserver o : listeners) {
			o.pluginStateChanged(plugin, newState, oldState);
		}
	}
}
