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
 * WS-Attacker will represent this as a checkbox.
 */
public abstract class AbstractOptionBoolean extends AbstractOption {
	private static final long serialVersionUID = 1L;
	
	private boolean on;
	
	public AbstractOptionBoolean(String name, boolean on) {
		this(name, on, "");
	}
	
	public AbstractOptionBoolean(String name, boolean on, String description) {
		super(name, description);
		this.on = on;
	}
	
	public boolean isOn() {
		return on;
	}
	
	public boolean setOn(boolean on) {
		if(isValid(on)) {
			this.on = on;
			notifyValueChanged();
			return true;
		}
		return false;
	}
	public boolean parseValue(String value) {
		if(isValid(value)) {
			setOn(new Boolean(value));
			return true;
		}
		return false;
	}
	public String getValueAsString() {
		return (new Boolean(on)).toString();
	}
	
	public abstract boolean isValid(boolean on);
}
