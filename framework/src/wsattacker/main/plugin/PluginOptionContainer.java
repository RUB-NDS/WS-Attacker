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

import wsattacker.main.composition.plugin.PluginOptionContainerObserver;
import wsattacker.main.composition.plugin.PluginOptionValueObserver;
import wsattacker.main.composition.plugin.option.AbstractOption;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.HashSet;

import org.apache.log4j.Logger;

/**
 * A container class for holding and managing plugin options
 * @author Christian Mainka
 *
 */
public class PluginOptionContainer implements Iterable<AbstractOption>, Serializable {
	private static final long serialVersionUID = 1L;
	
	private static Logger log = Logger.getLogger(PluginOptionContainer.class);
	
	private List<AbstractOption> options;
	transient private Set<PluginOptionContainerObserver> containerObservers;
	transient private Set<PluginOptionValueObserver> valueObservers;
	
	public PluginOptionContainer() {
		this.options = new ArrayList<AbstractOption> ();
		this.containerObservers = new HashSet<PluginOptionContainerObserver>(); // observers for observing the container state
		this.valueObservers = new HashSet<PluginOptionValueObserver>(); // observer for observing option values
	}
	/**
	 * Adds an AbstractOption to the container
	 * @param o
	 * @return the container (for multi adding)
	 */
	public PluginOptionContainer add(AbstractOption o) {
		return add(options.size(), o);
	}
	
	/**
	 * Adds an AbstractOption to the container at a specified position
	 * @param position
	 * @param option
	 * @return the container (for multi adding)
	 */
	public PluginOptionContainer add(int position, AbstractOption o) {
		AbstractOption search = getByName(o.getName());
		if (search != null) {
			log.warn("Trying to add an option with an existing name... option not added! Please consult the plugin maintainer!");
			return this;
		}
		options.add(position, o);
		o.setCollection(this);
		notifyPluginOptionContainerOptionAdded(position);
		return this;
	}
	
	/**
	 * removes an AbstractOption from the container
	 * @param option
	 * @return the container (for multi adding)
	 */
	public PluginOptionContainer remove(AbstractOption o) {
		if(options.contains(o)) {
			options.remove(o);
			o.setCollection(null);
		}
		notifyPluginOptionContainerOptionRemoved(o);
		return this;
	}
	
	public boolean contains(AbstractOption o) {
		return options.contains(o);
	}

	public void clear() {
		for(AbstractOption o : options) {
			remove(o);
		}
	}
	
	/**
	 * Gets an option by its index
	 * @param index
	 * @return the option
	 */
	public AbstractOption getByIndex(int index) {
		return options.get(index);
	}
	
	/**
	 * Gets an option by its name
	 * @param name
	 * @return the option
	 */
	public AbstractOption getByName(String name) {
		for(AbstractOption option : options) {
			if (option.getName().equals(name)) {
				return option;
			}
		}
		return null;
	}
	
	/**
	 * gets the index of an option
	 * this can be used for adding options after/before another
	 * @param option
	 * @return the index of the option
	 */
	public int indexOf(AbstractOption option) {
		return options.indexOf(option);
	}
	
	/**
	 * count the contained options
	 * @return size
	 */
	public int size() {
		return options.size();
	}

	@Override
	public Iterator<AbstractOption> iterator() {
		return options.iterator();
	}
	
	// Observer

	/**
	 * Add a plugin container observer
	 * The observer will be notified if a new options is added or an options is removed.
	 */
	public void addPluginOptionContainerObserver(PluginOptionContainerObserver o) {
		containerObservers.add(o);
	}

	public void removePluginOptionContainerObserver(PluginOptionContainerObserver o) {
		containerObservers.remove(o);
	}
	
	/**
	 * Add a plugin value observer
	 * The obsever will be notified if an option contained in this container changed its value
	 * @param o
	 */
	public void addPluginValueContainerObserver(PluginOptionValueObserver o) {
		valueObservers.add(o);
	}

	public void removePluginValueContainerObserver(PluginOptionValueObserver o) {
		valueObservers.remove(o);
	}
	
	private void notifyPluginOptionContainerOptionAdded(int index) {
		for(PluginOptionContainerObserver o : containerObservers) {
			o.optionContainerOptionAdded(this, index);
		}
	}
	
	private void notifyPluginOptionContainerOptionRemoved(AbstractOption removedOption) {
		for(PluginOptionContainerObserver o : containerObservers) {
			o.optionContainerOptionRemoved(this, removedOption);
		}
	}
	
	private void notifyPluginOptionValueChanged(AbstractOption option) {
		for(PluginOptionValueObserver o : valueObservers) {
			o.optionValueChanged(option);
		}
	}
	
	/**
	 * this method will be called by the contained options
	 * @param option
	 */
	public void optionValueChanged(AbstractOption option) {
		notifyPluginOptionValueChanged(option);
	}
}
