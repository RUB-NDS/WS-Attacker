/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.plugin.intelligentdos.ui.renderer;

import java.awt.Component;
import java.awt.Image;

import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;

import wsattacker.library.intelligentdos.common.SuccessfulAttack;

/**
 * @author Christian Altmeier
 */
public final class EfficiencyRenderer
    extends DefaultTreeCellRenderer
{

    private static final String IMAGE_INEFFICIENT = "/images/circle_green.png";

    private static final String IMAGE_EFFICIENT = "/images/circle_yellow.png";

    private static final String IMAGE_HIGHLY = "/images/circle_red.png";

    @Override
    public Component getTreeCellRendererComponent( JTree tree, Object value, boolean selected, boolean expanded,
                                                   boolean leaf, int row, boolean hasFocus )
    {

        super.getTreeCellRendererComponent( tree, value, selected, expanded, leaf, row, hasFocus );

        if ( leaf && !tree.getModel().getRoot().equals( value ) )
        {
            SuccessfulAttack sa = (SuccessfulAttack) ( (DefaultMutableTreeNode) value ).getUserObject();

            ImageIcon icon;
            switch ( sa.getEfficiency() )
            {
                case efficient:
                    icon = new ImageIcon( this.getClass().getResource( IMAGE_EFFICIENT ) );
                    break;
                case highlyEfficient:
                    icon = new ImageIcon( this.getClass().getResource( IMAGE_HIGHLY ) );
                    break;
                default:
                    // inefficient
                    icon = new ImageIcon( this.getClass().getResource( IMAGE_INEFFICIENT ) );
                    break;
            }

            icon.setImage( icon.getImage().getScaledInstance( 15, 15, Image.SCALE_DEFAULT ) );
            setIcon( icon );
            setText( "attack" );
        }

        return this;
    }
}
