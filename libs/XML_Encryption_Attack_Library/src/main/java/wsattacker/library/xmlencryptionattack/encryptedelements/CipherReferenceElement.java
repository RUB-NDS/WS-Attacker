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

package wsattacker.library.xmlencryptionattack.encryptedelements;

import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.DEFAULT_IDX;
import org.w3c.dom.Element;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis Kupser
 */
public class CipherReferenceElement
    extends AbstractRefElement
    implements CipherDataChildIF
{

    /**
     * @param cipherRef
     */
    public CipherReferenceElement( Element cipherRef )
    {
        this.m_Reference = cipherRef;
        m_URI = m_Reference.getAttribute( "URI" );

        if ( null != m_URI )
        {
            this.m_ReferredElement = getReferredElementFromURI( m_URI, this.m_Reference, DEFAULT_IDX );
        }
        else
            throw new IllegalArgumentException( "CipherReferenceElement: XPath reference? not supported yet" );
    }

    /**
     * @return
     */
    @Override
    public String getEncryptedData()
    {
        return DomUtilities.domToString( m_ReferredElement );
    }

    /**
     * @param payload
     */
    @Override
    public void setEncryptedData( String payload )
    {
        m_ReferredElement.setTextContent( payload );
    }

}