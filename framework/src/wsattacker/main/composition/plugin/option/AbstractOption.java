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

package wsattacker.main.composition.plugin.option;

import java.io.Serializable;

import wsattacker.main.plugin.PluginOptionContainer;

/**
 * Interface for a very basic option
 * Does not have any setters except for the string parser
 * All plugin options inherit this interface
 * @author Christian Mainka
 *
 */
public abstract class AbstractOption implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private PluginOptionContainer collection = null;
	private String name, description;
	
	/**
	 * Constructor for creating an option with at least a name and a description
	 * @param name
	 * @param description
	 */
	public AbstractOption(String name, String description) {
		this.name = name;
		this.description = description;
	}
	
	/**
	 * Constructor for creating an option with a name and an empty description
	 * Each option must have a name
	 * @param name
	 */
	public AbstractOption(String name) {
		this(name,"");
	}
	
	/**
	 * Each option belongs to exactly one PlugionOptionContainer
	 * This method will return it
	 * @see PluginOptionContainer
	 * @return
	 */
	public final PluginOptionContainer getCollection() {
		return collection;
	}
	/**
	 * Each option belongs to exactly one PlugionOptionContainer
	 * This method will set it
	 * @see PluginOptionContainer
	 * @param collection
	 */
	public final void setCollection(PluginOptionContainer collection) {
		this.collection = collection;
	}
	
	protected final void notifyValueChanged() {
		if(collection != null) {
			collection.optionValueChanged(this);
		}
	}
	
	public String getName() {
		return name;
	}
	public String getDescription() {
		return description;
	}
	
	/**
	 * Each option has a isValid() method
	 * It must at least work for a String parameter, although there will be
	 * different parameter types for e.g. Integer options
	 * @param value
	 * @return true if value is valid
	 */
	public abstract boolean isValid(String value); // only for generic proposals
	
	/**
	 * Each option can parse a String value
	 * @param value
	 * @return true if value was valid and is set
	 */
	public abstract boolean parseValue(String value); // only for generic proposals
	
	/**
	 * Each option can return a String representation of its value
	 * @return
	 */
	public abstract String getValueAsString(); // only for generic proposals
}