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

package wsattacker.gui.composition;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;

/**
* This code was edited or generated using CloudGarden's Jigloo
* SWT/Swing GUI Builder, which is free for non-commercial
* use. If Jigloo is being used commercially (ie, by a corporation,
* company or business for any purpose whatever) then you
* should purchase a license for each developer using Jigloo.
* Please visit www.cloudgarden.com for details.
* Use of Jigloo implies acceptance of these licensing terms.
* A COMMERCIAL LICENSE HAS NOT BEEN PURCHASED FOR
* THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED
* LEGALLY FOR ANY CORPORATE OR COMMERCIAL PURPOSE.
*/
public abstract class AbstractOptionGUI extends javax.swing.JPanel {
	private static final long serialVersionUID = 1L;
	private AbstractPlugin plugin;
	private ControllerInterface controller;
	private AbstractOption option;
	
	public AbstractOptionGUI() {
		super();
		plugin = null;
		controller = null;
	}
	
	public AbstractOptionGUI(ControllerInterface controller, AbstractPlugin plugin, AbstractOption option) {
		super();
		setName(option.getName());
		this.plugin = plugin;
		this.controller = controller;
		this.option = option;
	}
	
	
	final protected ControllerInterface getController() {
		return controller;
	}
	
	final protected AbstractOption getOption() {
		return option;
	}
	
	final protected AbstractPlugin getPlugin() {
		return plugin;
	}
	
	public abstract void saveValue();
	public abstract void checkValue();
	public abstract void reloadValue();

}
