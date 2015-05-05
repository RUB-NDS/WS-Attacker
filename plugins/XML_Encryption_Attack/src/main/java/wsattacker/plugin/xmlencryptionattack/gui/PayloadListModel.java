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

package wsattacker.plugin.xmlencryptionattack.gui;

import java.util.ArrayList;
import java.util.List;
import javax.swing.AbstractListModel;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;

/**
 * @author Dennis
 */
public class PayloadListModel
    extends AbstractListModel<AbstractEncryptionElement>
{
    private final List<AbstractEncryptionElement> m_Payloads;

    public PayloadListModel( final List<AbstractEncryptionElement> payloads )
    {
        this.m_Payloads = new ArrayList<AbstractEncryptionElement>( payloads );
    }

    @Override
    public int getSize()
    {
        return m_Payloads.size();
    }

    @Override
    public AbstractEncryptionElement getElementAt( int index )
    {
        return m_Payloads.get( index );
    }
}
