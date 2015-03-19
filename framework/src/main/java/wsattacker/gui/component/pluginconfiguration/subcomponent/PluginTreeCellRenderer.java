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
package wsattacker.gui.component.pluginconfiguration.subcomponent;

import it.cnr.imaa.essi.lablib.gui.checkboxtree.DefaultCheckboxTreeCellRenderer;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTree;
import org.apache.log4j.Logger;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.util.Category;

public class PluginTreeCellRenderer
    extends DefaultCheckboxTreeCellRenderer
{

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = Logger.getLogger( PluginTreeCellRenderer.class );

    public static final String PROP_PLUGINTREE = "pluginTree";

    private JTree pluginTree;

    public PluginTreeCellRenderer()
    {
    }

    public JTree getPluginTree()
    {
        return pluginTree;
    }

    public void setPluginTree( PluginTree pluginTree )
    {
        JTree oldPluginTree = this.pluginTree;
        this.pluginTree = pluginTree;
        super.firePropertyChange( "pluginTree", oldPluginTree, pluginTree );
    }

    @Override
    public Component getTreeCellRendererComponent( JTree tree, Object value, boolean selected, boolean expanded,
                                                   boolean leaf, int row, boolean hasFocus )
    {
        Component defaultCell =
            super.getTreeCellRendererComponent( tree, value, selected, expanded, leaf, row, hasFocus );
        JLabel additionalText = new JLabel();
        additionalText.setFont( new Font( "Dialog", 2, 12 ) );
        JPanel newCell = new JPanel();
        newCell.setLayout( new FlowLayout( 0, 0, 0 ) );
        newCell.setOpaque( false );
        newCell.add( defaultCell );
        newCell.add( additionalText );
        if ( value instanceof Category )
        {
            additionalText.setText( String.format( "(%d)",
                                                   new Object[] { Integer.valueOf( ( (Category) value ).getLeafsRecursive().size() ) } ) );
        }
        else if ( value instanceof AbstractPlugin )
        {
            AbstractPlugin plugin = (AbstractPlugin) value;
            additionalText.setText( String.format( "(%s)", new Object[] { plugin.getState() } ) );
        }
        else
        {
            LOG.warn( ( new StringBuilder() ).append( "Does not expect class: " ).append( value.getClass() ).toString() );
        }
        return newCell;
    }
}
