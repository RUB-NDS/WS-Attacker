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

import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;

/**
 * This class represents the DataReference element of an EncryptedKey element. It is only possible to refer an
 * EncryptedData element with an DataReference element.
 * 
 * @author Dennis Kupser
 */
public class DataReferenceElement
    extends AbstractRefElement
{
    private EncryptedDataElement m_RefEncData;

    private final int m_DataRefIdx;

    /**
     * @return
     */
    public int getDataRefIdx()
    {
        return m_DataRefIdx;
    }

    /**
     * Get the referring EncryptedDataElement object
     * 
     * @return
     */
    public EncryptedDataElement getRefEncData()
    {
        return m_RefEncData;
    }

    /**
     * Construct an DataReferenceElement object with an dataRef element and its URI
     * 
     * @param dataRef
     * @param dataIdx
     */
    public DataReferenceElement( Element dataRef, int dataIdx )
    {
        this.m_DataRefIdx = dataIdx;
        this.m_Reference = (Element) dataRef;
        this.m_URI = m_Reference.getAttribute( "URI" );

        if ( null != m_URI )
        {
            this.m_ReferredElement = (Element) getReferredElementFromURI( m_URI, m_Reference, m_DataRefIdx );
            if ( m_ReferredElement.getLocalName().equalsIgnoreCase( "EncryptedData" ) )
                m_RefEncData = new EncryptedDataElement( m_ReferredElement );
            else
                throw new IllegalArgumentException( "DataReference-object must reference an encrypteddata element!" );
        }
        else
            throw new IllegalArgumentException( "CipherReferenceElement: XPath reference? not supported yet" );

    }
}