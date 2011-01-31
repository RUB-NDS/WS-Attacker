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

import java.io.File;

/**
 * WS-Attacker will represent this with a file picker. 
 */
public abstract class AbstractOptionFile extends AbstractOption {
	private static final long serialVersionUID = 1L;
	
	File file;
	
	protected AbstractOptionFile(String name, String description) {
		super(name, description);
		this.file = null;
	}

	@Override
	public boolean isValid(String value) {
		try {
			File test = new File(value);
			return isValid(test);
		}
		catch (Exception e) {
			return false;
		}
	}
	
	public abstract boolean isValid(File file);

	@Override
	public boolean parseValue(String value) {
		if(isValid(value)) {
			return setFile(new File(value));
		}
		return false;
	}
	
	public boolean setFile(File file) {
		if(isValid(file)) {
			this.file = file;
			notifyValueChanged();
			return true;
		}
		return false;
	}

	@Override
	public String getValueAsString() {
		return (file==null)?"":file.toString();
	}
	
	public File getValue() {
		return file;
	}

}
