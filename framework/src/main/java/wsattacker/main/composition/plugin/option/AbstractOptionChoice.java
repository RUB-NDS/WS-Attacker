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

import java.util.List;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.gui.component.pluginconfiguration.option.OptionChoiceGUI_NB;

/**
 * WS-Attacker will represent this as a drop-down list.
 */
public abstract class AbstractOptionChoice extends AbstractOption {

	private static final long serialVersionUID = 2L;

	protected AbstractOptionChoice(String name, String description) {
		super(name, description);
	}

	public abstract List<String> getChoices();

	public abstract void setChoices(List<String> choicesList);

	public abstract void setSelectedAsString(String value);

	public abstract String getSelectedAsString();

	@Override
	public String getValueAsString() {
		return getSelectedAsString();
	}

	public abstract void setSelectedIndex(int index);

	public abstract int getSelectedIndex();

	public abstract boolean isValid(int choice);

	@Override
	public OptionGUI createOptionGUI() {
		return new OptionChoiceGUI_NB(this);
	}
}
