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
package wsattacker.main.composition.plugin.option;

import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.gui.component.pluginconfiguration.option.OptionBooleanGUI_NB;

/**
 * WS-Attacker will represent this as a checkbox.
 */
public abstract class AbstractOptionBoolean extends AbstractOption {

	private static final long serialVersionUID = 2L;
	public static final String PROP_ON = "on";
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

	public void setOn(boolean on) {
		if (isValid(on)) {
			boolean oldOn = this.on;
			this.on = on;
			firePropertyChange(PROP_ON, oldOn, on);
		} else {
			throw new IllegalArgumentException(String.format("isValid(%s) returned false", on));
		}
	}

	@Override
	public void parseValue(String value) {
		if (isValid(value)) {
			setOn(Boolean.valueOf(value));
		} else {
			throw new IllegalArgumentException(String.format("isValid(\"%s\") returned false", value));
		}
	}

	@Override
	public String getValueAsString() {
		return String.format("%b", isOn());
	}

	public abstract boolean isValid(boolean on);

	@Override
	public OptionGUI createOptionGUI() {
		return new OptionBooleanGUI_NB(this);
	}
}
