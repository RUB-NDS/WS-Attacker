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

import wsattacker.main.composition.plugin.option.AbstractOptionInteger;

public class OptionLimitedInteger extends AbstractOptionInteger {
	private static final long serialVersionUID = 1L;
	private int min,max;
	
	public OptionLimitedInteger(String name, int value, int min, int max) {
		super(name, value);
		this.min = min;
		this.max = max;
	}
	
	public OptionLimitedInteger(String name, int value, String description, int min, int max) {
		super(name, value, description);
		this.min = min;
		this.max = max;
	}

	public int getMax() {
		return this.max;
	}

	public void setMax(int max) {
		this.max = max;
	}

	public int getMin() {
		return this.min;
	}

	public void setMin(int min) {
		this.min = min;
	}
	
	@Override
	public boolean isValid(String value) {
		try {
			int i = Integer.parseInt(value);
			return isValid(i);
		}
		catch(Exception e) {
			return false;
		}
	}

	@Override
	public boolean isValid(int value) {
		return (value >= this.min) && (value <= this.max);
	}

}
