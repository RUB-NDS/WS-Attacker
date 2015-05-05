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

import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * This class represents the EncryptedKey element of the XML Encryption. It is only possible to refer an EncryptedData
 * or an EncryptedKey. The class EncryptedKeyElement extends from the AbstractEncryptionElement which initialize the
 * encrypted objects.
 * 
 * @author Dennis Kupser
 */
public class EncryptedKeyElement
    extends AbstractEncryptionElement
{
    private final List<AbstractRefElement> m_ReferenceElementList;

    private EncryptedDataElement m_EnwrapEncData = null;

    private int m_WrappingEncDataIndex = 0;

    public int getWrappingEncDataIndex()
    {
        return m_WrappingEncDataIndex;
    }

    public void setWrappingEncDataIndex( int wrappingEncDataIndex )
    {
        this.m_WrappingEncDataIndex = wrappingEncDataIndex;
    }

    /**
     * Get the ReferenceList of an EncryptedKeyElement object.
     * 
     * @return list of references (keyreferences or datareferences possible)
     */
    public List<AbstractRefElement> getReferenceElementList()
    {
        return m_ReferenceElementList;
    }

    /**
     * Construct an EncryptedKeyElement object with an encKeyElement. Distinguishing between KeyReference and
     * DataReference. Every EncryptedKeyElement object has at least one reference except that the EncryptedKeyElement is
     * part of an EncrypteDataElement.
     * 
     * @param encKeyElement
     */
    public EncryptedKeyElement( Element encKeyElement )
    {
        List<Element> refKeyList = null;
        List<Element> dataReflist;
        this.m_EncryptedElement = encKeyElement;
        this.m_ReferenceElementList = new ArrayList();
        initEncryptionElement( encKeyElement );

        refKeyList = DomUtilities.findChildren( encKeyElement, "ReferenceList", URI_NS_ENC );

        if ( 1 == refKeyList.size() )
        {
            dataReflist = DomUtilities.findChildren( refKeyList.get( 0 ), "DataReference", URI_NS_ENC );

            for ( int i = 0; dataReflist.size() > i; i++ )
            {
                m_ReferenceElementList.add( new DataReferenceElement( dataReflist.get( i ), i ) );
            }

            dataReflist = DomUtilities.findChildren( refKeyList.get( 0 ), "KeyReference", URI_NS_ENC );

            for ( Element dataRefEle : dataReflist )
            {
                m_ReferenceElementList.add( new KeyReferenceElement( dataRefEle ) );
            }

        }
        // else // EncryptedKey is part of an EncryptedData element
        // LOG.info("EncryptedKey without ReferenceList detected.");
        // throw new
        // IllegalArgumentException("parameter 'cipherDataChild'->CipherReference size must not be bigger than one");
    }

    public void setEnwrapEncData( EncryptedDataElement encData )
    {
        this.m_EnwrapEncData = encData;
    }

    public EncryptedDataElement getEnwrapEncData()
    {
        return m_EnwrapEncData;
    }

    public boolean hasEnwrapEncData()
    {
        if ( null == m_EnwrapEncData )
        {
            return false;
        }
        else
        {
            return true;
        }
    }
}