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

import java.io.File;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.gui.component.pluginconfiguration.option.OptionFileGUI_NB;

/**
 * WS-Attacker will represent this with a file picker.
 */
public abstract class AbstractOptionFile extends AbstractOption {

	private static final long serialVersionUID = 2L;
	public static final String PROP_FILE = "file";
	private File file = null;

	protected AbstractOptionFile(String name, String description) {
		super(name, description);
		this.file = null;
	}

	public File getFile() {
		return file;
	}

	public void setFile(File file) {
		if (isValid(file)) {
			File oldFile = this.file;
			this.file = file;
			firePropertyChange(PROP_FILE, oldFile, file);
		} else {
			throw new IllegalArgumentException(String.format("isValid(\"%s\") returned false", file));
		}
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
	public void parseValue(String value) {
		if (isValid(value)) {
			setFile(new File(value));
		} else {
			throw new IllegalArgumentException(String.format("isValid(\"%s\") returned false", value));
		}
	}

	@Override
	public String getValueAsString() {
		return (file == null) ? "" : file.toString();
	}

	@Override
	public OptionGUI createOptionGUI() {
		return new OptionFileGUI_NB(this);
	}
}
