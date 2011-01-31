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

import java.io.Serializable;
import java.util.Iterator;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.util.SortedUniqueList;

/**
 * A class for holding plugins
 * Can be seen as a kind of List<AbstractPlugin> but with less features
 * Each plugin can occur only once
 * @author Christian Mainka
 *
 */
public class PluginContainer implements Iterable<AbstractPlugin>, Serializable {
	private static final long serialVersionUID = 1L;
	
	private SortedUniqueList<AbstractPlugin> plugins;

	public PluginContainer() {
		plugins = new SortedUniqueList<AbstractPlugin>();
	}
	
	/**
	 * Get the index of a plugin
	 * @param plugin
	 * @return index
	 */
	public int indexOf(AbstractPlugin plugin) {
		return plugins.indexOf(plugin);
	}
	
	/**
	 * Get plugin by its name
	 * @param pluginName
	 * @return AbstractPlugin
	 */
	public AbstractPlugin getByName(String pluginName) {
		for(AbstractPlugin plugin : plugins) {
			if(plugin.getName().equals(pluginName))
				return plugin;
		}
		return null;
	}
	
	/**
	 * Get plugin by its index
	 * @param index
	 * @return AbstractPlugin
	 */
	public AbstractPlugin getByIndex(int index) {
		return plugins.get(index);
	}

	/**
	 * Add a plugin to the container
	 * @param plugin
	 * @return true if container changed
	 */
	public boolean add(AbstractPlugin plugin) {
		return plugins.add(plugin);
	}
	
	/**
	 * Remove a plugin from this container by its unique name
	 * @param pluginName
	 * @return true if container changed
	 */
	public boolean removeByName(String pluginName) {
		AbstractPlugin toRemove = getByName(pluginName);
		return remove(toRemove);
	}
	
	/**
	 * Remove a plugin from this container by its index
	 * @param index
	 * @return true if container changed
	 */
	public boolean removeByIndex(int index) {
		AbstractPlugin toRemove = getByIndex(index);
		return remove(toRemove);
	}
	
	/**
	 * Remove a plugin from this container
	 * @param plugin
	 * @return true if container changed
	 */
	public boolean remove(AbstractPlugin plugin) {
		return plugins.remove(plugin);
	}
	
	public void clear() {
		plugins.clear();
	}
	
	public int size() {
		return plugins.size();
	}
	
	public boolean contains(AbstractPlugin plugin) {
		return plugins.contains(plugin);
	}

	@Override
	public Iterator<AbstractPlugin> iterator() {
		return plugins.iterator();
	}


}
