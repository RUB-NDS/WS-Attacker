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
import javax.swing.JList;
import javax.swing.plaf.basic.BasicComboBoxRenderer;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse.Result;

/**
 * @author Dennis
 */
public class ResultTableCellRenderer
    extends BasicComboBoxRenderer
{
    @Override
    public Component getListCellRendererComponent( JList list, Object value, int index, boolean isSelected,
                                                   boolean cellHasFocus )
    {
        super.getListCellRendererComponent( list, value, index, isSelected, cellHasFocus );

        if ( value != null )
        {
            Result res = (Result) value;
            setText( res.toString() );
        }

        return this;
    }
}
