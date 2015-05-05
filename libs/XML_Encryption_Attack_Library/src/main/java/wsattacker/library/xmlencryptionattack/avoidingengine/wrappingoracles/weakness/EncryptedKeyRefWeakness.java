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

package wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness;

import java.util.List;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import static wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.WrapModeEnum.ENCKEY_WRAP_ENCDATA;
import static wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.WrapModeEnum.WRAP_ENCKEY_ENCDATA;
import static wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.WrapModeEnum.WRAP_ENCKEY_WRAP_ENCDATA;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class EncryptedKeyRefWeakness
    extends AbstractEncryptionWeakness
{
    private final static Logger LOG = Logger.getLogger( EncryptedKeyRefWeakness.class );

    public EncryptedKeyRefWeakness( AbstractEncryptionElement encPay, EncryptedKeyElement encKey )
    {
        this.m_EncKey = encKey;
        this.m_EncPay = encPay;
        determineEncSignMode( encPay, encKey );
        if ( ENCKEY_WRAP_ENCDATA == m_WrapMode || WRAP_ENCKEY_WRAP_ENCDATA == m_WrapMode )
        {
            this.m_PossibleWeaks = 3;
        }
        else if ( WRAP_ENCKEY_ENCDATA == m_WrapMode )
        {
            this.m_PossibleWeaks = 2;
        }
        else
            throw new IllegalArgumentException( "This mode could not have any EncryptedKeyRefWeaknesses" );
    }

    public EncryptedKeyRefWeakness( EncryptedKeyElement encKey )
    {
        this.m_EncKey = encKey;
    }

    @Override
    public int getPossibleNumWeaks()
    {
        return m_PossibleWeaks;
    }

    @Override
    public void abuseWeakness( int index, Element encKeyPay, Element encDataPay )
    {
        index %= m_PossibleWeaks;

        switch ( m_WrapMode )
        {
            case ENCKEY_WRAP_ENCDATA:
            case WRAP_ENCKEY_WRAP_ENCDATA:
                handleEncKeyWithWrapEncData( index, encKeyPay, encDataPay );
                break;
            case WRAP_ENCKEY_ENCDATA:
                handleEncKeyWithoutWrapEncData( index, encKeyPay, encDataPay );
                break;

            default:
                throw new IllegalArgumentException( "No valid EncSignMode in EncKeyRefWeakness" );
        }
    }

    private void handleEncKeyWithWrapEncData( int index, Element encKeyPay, Element encDataPay )
    {
        String newEncDataPayId = encDataPay.getAttribute( "Id" );
        // delete all -> no entries?!?
        switch ( index )
        {
        // 0) delete and append
            case 0:
                deleteOldEncKeyReference( encKeyPay );
                createNewEncKeyReference( newEncDataPayId, encKeyPay );
                break;
            // 1) only append
            case 1:
                createNewEncKeyReference( newEncDataPayId, encKeyPay );
                break;
            // 2) delete all
            case 2:
                deleteOldEncKeyReference( encKeyPay );
                break;

            default:

                String error = "Index out of range: '" + index + "'";
                LOG.warn( error );

        }
    }

    private void handleEncKeyWithoutWrapEncData( int index, Element encKeyPay, Element encDataPay )
    {
        switch ( index )
        {
        // 0) delete all
            case 0:
                deleteOldEncKeyReference( encKeyPay );
                break;
            // 2) keep ref
            case 1:
                LOG.info( "Hold elements in ReferenceList" );
                break;

            default:
                String error = "Index out of range: '" + index + "'";
                LOG.warn( error );
        }
    }

    public static void deleteOldEncKeyReference( Element keyElement )
    {
        List<Element> encKeyChilds = DomUtilities.getAllChildElements( keyElement );

        for ( int i = 0; encKeyChilds.size() > i; i++ )
        {
            if ( encKeyChilds.get( i ).getLocalName().equals( "ReferenceList" ) )
            {
                List<Element> refList = DomUtilities.getAllChildElements( encKeyChilds.get( i ) );

                for ( int j = 0; refList.size() > j; j++ )
                {

                    LOG.info( "Remove element in ReferenceList element: "
                        + encKeyChilds.get( i ).removeChild( refList.get( j ) ).getLocalName() );
                }
            }
        }
    }

    public static void deleteOldEncKeyReference( Element keyElement, String encDataId )
    {
        List<Element> encKeyChilds = DomUtilities.getAllChildElements( keyElement );

        for ( int i = 0; encKeyChilds.size() > i; i++ )
        {
            if ( encKeyChilds.get( i ).getLocalName().equals( "ReferenceList" ) )
            {
                List<Element> refList = DomUtilities.getAllChildElements( encKeyChilds.get( i ) );

                for ( int j = 0; refList.size() > j; j++ )
                {
                    NamedNodeMap attrs = refList.get( j ).getAttributes();

                    for ( int k = 0; attrs.getLength() > k; k++ )
                    {
                        if ( attrs.item( k ).getNodeValue().contains( encDataId ) )
                        {
                            LOG.info( "Remove element in ReferenceList element: "
                                + encKeyChilds.get( i ).removeChild( refList.get( j ) ).getLocalName() );

                        }
                    }

                }
            }
        }
    }

    public static void createNewEncKeyReference( String idVal, Element keyElement )
    {
        if ( !idVal.equals( "" ) )
        {
            String prefix = keyElement.getPrefix();
            String namespaceURI = keyElement.lookupNamespaceURI( prefix );
            List<Element> refElement = DomUtilities.findChildren( keyElement, "ReferenceList", namespaceURI, true );
            Element newDataRef = null;
            String newURI = null;

            if ( null != prefix )
                newDataRef =
                    keyElement.getOwnerDocument().createElementNS( namespaceURI, prefix + ":" + "DataReference" );
            else
                newDataRef = keyElement.getOwnerDocument().createElement( "DataReference" );

            newURI = idVal;
            newDataRef.setAttribute( "URI", "#" + newURI );
            refElement.get( 0 ).appendChild( newDataRef );
            LOG.info( "Append new child in ReferenceList: "
                + refElement.get( 0 ).appendChild( newDataRef ).getLocalName() + "->" + "URI: " + newURI );
        }
        else
            throw new IllegalArgumentException( "No Id-Attribute but Id has to change?" );
    }

}
