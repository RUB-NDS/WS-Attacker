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
package wsattacker.library.xmlencryptionattack.encryptedelements.key;

import java.util.List;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * This class represents the KeyInfo element of an encrypted element (EncryptedKey or EncryptedData). It is possible
 * that an EncryptedDataElement object has an EncryptedKeyElement object inside the KeyInfoElement object.
 * 
 * @author Dennis Kupser
 */
public class KeyInfoElement
{
    private EncryptedKeyElement m_EncryptedKeyElement = null;

    private Element m_KeyInfoEl = null;

    protected final static Logger LOG = Logger.getLogger( KeyInfoElement.class );

    /**
     * Construct an KeyInfoElement object and detect a possible EncryptedKey
     * 
     * @param keyInfo
     */
    public KeyInfoElement( Element keyInfo )
    {
        this.m_KeyInfoEl = keyInfo;
        List<Element> encKeys = DomUtilities.findChildren( keyInfo, "EncryptedKey", URI_NS_ENC, true );

        if ( 0 < encKeys.size() )
        {
            this.m_EncryptedKeyElement = new EncryptedKeyElement( encKeys.get( 0 ) );
            LOG.debug( "EncryptedKey in KeyInfo-Element detected." );
        }
    }

    /**
     * Get KeyInfo element of an encrypted element.
     * 
     * @return
     */
    public Element getKeyInfoElement()
    {
        return m_KeyInfoEl;
    }

    /**
     * Get the EncryptedKeyElement object of the KeyInfoElement object
     * 
     * @return
     */
    public EncryptedKeyElement getEncryptedKeyElement()
    {
        return m_EncryptedKeyElement;
    }
}