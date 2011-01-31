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

import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;

public class OptionSimpleVarchar extends AbstractOptionVarchar {
	private static final long serialVersionUID = 1L;
	int maxLength;
	
	public OptionSimpleVarchar(String name, String value) {
		super(name, value, 0);
		this.maxLength = 0;
	}

	public OptionSimpleVarchar(String name, String value, String description) {
		super(name, value, description, 0);
		this.maxLength = 0;
	}

	public OptionSimpleVarchar(String name, String value, int maxLength) {
		super(name, value, maxLength);
		this.maxLength = maxLength;
	}

	public OptionSimpleVarchar(String name, String value, String description,
			int maxLength) {
		super(name, value, description, maxLength);
		this.maxLength = maxLength;
	}

	@Override
	public int getMaxLength() {
		return this.maxLength;
	}

	public void setMaxLength(int max) {
		this.maxLength = max;
	}

	@Override
	public boolean isValid(String value) {
		if (value.contains(System.getProperty("line.separator")))
			return false;
		if ( (this.maxLength > 0) && (value.length() > this.maxLength) )
			return false;
		return true;
	}
}
