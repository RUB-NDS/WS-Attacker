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

/**
 * WS-Attacker will represent this with a text input field for multiple lines. 
 */
public abstract class AbstractOptionString extends AbstractOption {
	private static final long serialVersionUID = 1L;
	
	private String value;
	
	// constructors
	public AbstractOptionString(String name, String value) {
		this(name, value, "");
	}
	
	public AbstractOptionString(String name, String value, String description) {
		super(name, description);
		this.value = value;
	}
	
	// IMPORTANT: Implementation needed
	public abstract boolean isValid(String value);
	
	public boolean parseValue(String value) {
		if(isValid(value)) {
			this.value = value;
			notifyValueChanged();
			return true;
		}
		return false;
	}
	public String getValueAsString() {
		return value;
	}
	
	// String specific
	public String getValue() {
		return getValueAsString();
	}
	public boolean setValue(String value) {
		return parseValue(value);
	}
}
