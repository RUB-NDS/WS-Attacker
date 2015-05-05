/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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

package wsattacker.plugin.xmlencryptionattack.serverbehaviour.gui;

import java.awt.Component;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.table.TableCellRenderer;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;
import static wsattacker.library.xmlutilities.dom.DomUtilities.stringToDom;

/**
 * @author Dennis
 */
public class MultiLinesCellRenderer
    extends JTextArea
    implements TableCellRenderer
{
    @Override
    public Component getTableCellRendererComponent( JTable table, Object value, boolean isSelected, boolean hasFocus,
                                                    int row, int column )
    {
        Document resp = null;
        if ( null != value )
        {
            try
            {
                resp = stringToDom( value.toString() );
            }
            catch ( SAXException ex )
            {
                Logger.getLogger( MultiLinesCellRenderer.class.getName() ).log( Level.SEVERE, null, ex );
            }

            if ( null != resp )
                setText( domToString( resp, true ) );
            else
                setText( value.toString() );

        }
        else
            setText( "" );
        return this;
    }

}
