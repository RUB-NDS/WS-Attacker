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
package wsattacker.gui.component.pluginconfiguration.composition;

import java.awt.Color;
import javax.swing.JPanel;
import wsattacker.main.composition.plugin.option.AbstractOption;

/**
 * @author christian
 */
public abstract class OptionGUI
    extends JPanel
{

    final public static Color COLOR_ERROR = new Color( 255, 153, 153 );

    final public static Color COLOR_OK = Color.WHITE;

    public abstract void bindingDoUnbind();

    public abstract AbstractOption getUsedOption();
}
