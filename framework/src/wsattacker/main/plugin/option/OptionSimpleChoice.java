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

package wsattacker.main.plugin.option;

import java.util.List;

import wsattacker.main.composition.plugin.option.AbstractOptionChoice;

public class OptionSimpleChoice extends AbstractOptionChoice {
	private static final long serialVersionUID = 1L;
	List<String> choices;
	int selected;
	
	public OptionSimpleChoice(String name, List<String> choices, int selected) {
		this(name, choices, selected, "");
	}
	
	public OptionSimpleChoice(String name, List<String> choices, int selected, String description) {
		super(name, description);
		this.choices = choices;
		if((selected >= 0) && (selected < choices.size())) {
			this.selected = selected;
		}
	}

	@Override
	public boolean isValid(int choice) {
		return ((choice >= 0) && (choice < choices.size()));
	}

	@Override
	public boolean isValid(String value) {
		return choices.contains(value);
	}

	@Override
	public boolean parseValue(String value) {
		if (isValid(value)) {
			setChoice(choices.indexOf(value));
			return true;
		}
		return false;
	}

	@Override
	public String getValueAsString() {
		return choices.get(selected);
	}

	@Override
	public List<String> getChoices() {
		return choices;
	}

	@Override
	public boolean setChoice(String value) {
		return parseValue(value);
	}

	@Override
	public boolean setChoice(int index) {
		if(isValid(index)) {
			selected = index;
			notifyValueChanged();
			return true;
		}
		return false;
	}

	@Override
	public int getChoice() {
		return selected;
	}


}
