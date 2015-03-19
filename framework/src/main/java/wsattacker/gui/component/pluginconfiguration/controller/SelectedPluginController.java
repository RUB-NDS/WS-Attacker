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
package wsattacker.gui.component.pluginconfiguration.controller;

import org.jdesktop.beans.AbstractBean;
import wsattacker.gui.component.pluginconfiguration.subcomponent.DummyPlugin;
import wsattacker.main.composition.plugin.AbstractPlugin;

public class SelectedPluginController
    extends AbstractBean
{

    private static final AbstractPlugin DUMMYPLUGIN = new DummyPlugin();

    public static final String PROP_SELECTEDPLUGIN = "selectedPlugin";

    private AbstractPlugin selectedPlugin = DUMMYPLUGIN;

    /**
     * Get the value of selectedPlugin
     * 
     * @return the value of selectedPlugin
     */
    public AbstractPlugin getSelectedPlugin()
    {
        return selectedPlugin;
    }

    /**
     * Set the value of selectedPlugin
     * 
     * @param selectedPlugin new value of selectedPlugin
     */
    public void setSelectedPlugin( AbstractPlugin selectedPlugin )
    {
        AbstractPlugin newPlugin;
        if ( selectedPlugin == null )
        {
            newPlugin = DUMMYPLUGIN;
        }
        else
        {
            newPlugin = selectedPlugin;
        }
        AbstractPlugin oldSelectedPlugin = this.selectedPlugin;
        this.selectedPlugin = newPlugin;
        firePropertyChange( PROP_SELECTEDPLUGIN, oldSelectedPlugin, newPlugin );
    }
}
