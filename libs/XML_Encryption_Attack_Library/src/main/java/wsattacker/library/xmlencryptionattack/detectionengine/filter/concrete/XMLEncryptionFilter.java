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

package wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete;

import java.util.List;
import javax.xml.xpath.XPathExpressionException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter;
import static wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter.LOG;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class XMLEncryptionFilter
    extends AbstractDetectionFilter
{

    public XMLEncryptionFilter( DetectFilterEnum filterType )
    {
        this.mFilterType = filterType;
        this.m_OutputFilter = new EncryptionInfo( filterType );
    }

    @Override
    public AbstractDetectionInfo process()
    {
        try
        {
            if ( m_InputFilter != null )
            {
                detectEncryptedKeyElement();
                detectEncryptedDataElement();
            }
            else
                LOG.info( "Could not find any Input-File." );
        }
        catch ( XPathExpressionException ex )
        {
            LOG.error(ex);
        }

        return (EncryptionInfo) this.m_OutputFilter;
    }

    private void detectEncryptedKeyElement()
        throws XPathExpressionException
    {
        // detectionReport hinzufügen
        List<Element> encryptedKeyList;

        encryptedKeyList =
            (List<Element>) DomUtilities.evaluateXPath( m_InputFilter, "//*[local-name()='EncryptedKey' "
                + "and namespace-uri()='" + URI_NS_ENC + "']" );
        if ( 0 < encryptedKeyList.size() )
        {
            for ( Element enc : encryptedKeyList )
            {
                if ( !detectIsEncryptedKeyInEncryptedData( enc ) )
                {
                    ( (EncryptionInfo) m_OutputFilter ).addEncryptedKeyElements( new EncryptedKeyElement( enc ) );
                }
            }
        }
        else
        {
            LOG.info( "Could not find any EncryptedKey Elements." );
        }
    }

    private void detectEncryptedDataElement()
        throws XPathExpressionException
    {
        List<Element> encryptedDataList;

        encryptedDataList =
            (List<Element>) DomUtilities.evaluateXPath( m_InputFilter, "//*[local-name()='EncryptedData' "
                + "and namespace-uri()='" + URI_NS_ENC + "']" );

        if ( 0 < encryptedDataList.size() )
            filterEncDataWithoutExternEncKey( encryptedDataList );
        else
            LOG.info( "Could not find any EncryptedData Elements." );
    }

    private void filterEncDataWithoutExternEncKey( List<Element> encryptedDataList )
    {
        List<EncryptedKeyElement> encKeyList = ( (EncryptionInfo) m_OutputFilter ).getEncryptedKeyElements();

        if ( 0 < encKeyList.size() )
        {
            for ( int i = 0; encryptedDataList.size() > i; i++ )
            {
                Element refEncData = encryptedDataList.get( i );
                boolean isEncKeyData = false;
                for ( int j = 0; ( encKeyList.size() > j ) && !isEncKeyData; j++ )
                {
                    List<AbstractRefElement> refListEl = encKeyList.get( j ).getReferenceElementList();
                    for ( int k = 0; refListEl.size() > k; k++ )
                    {
                        if ( refListEl.get( k ).getReferredElement().isEqualNode( refEncData ) )
                        {
                            isEncKeyData = true;
                            break;
                        }
                    }
                }
                if ( !isEncKeyData )
                {
                    EncryptedDataElement encData = new EncryptedDataElement( refEncData );
                    ( (EncryptionInfo) m_OutputFilter ).addEncryptedDataElements( encData );
                    checkEncKeyInEncData( encData );
                }
            }
        }
        else
        {
            for ( Element enc : encryptedDataList )
            {
                EncryptedDataElement encData = new EncryptedDataElement( enc );
                checkEncKeyInEncData( encData );

                ( (EncryptionInfo) m_OutputFilter ).addEncryptedDataElements( encData );

                LOG.info( "Added EncryptedData without extern EncryptedKey." );
            }
        }
    }

    private void checkEncKeyInEncData( EncryptedDataElement encData )
    {
        if ( null != encData.getKeyInfoElement() )
        {
            EncryptedKeyElement encKey = encData.getKeyInfoElement().getEncryptedKeyElement();
            if ( null != encKey )
            {
                encKey.setEnwrapEncData( encData );
            }
        }
    }

    private boolean detectIsEncryptedKeyInEncryptedData( Element enc )
    {
        String namespaceURI = enc.lookupNamespaceURI( enc.getPrefix() );

        List<Element> refElement = DomUtilities.findChildren( enc, "ReferenceList", namespaceURI, true );

        if ( null != enc.getParentNode() && 0 == refElement.size() ) // simpler?
        {
            if ( enc.getParentNode().getLocalName().equals( "KeyInfo" ) )
            {
                Node parentNode = enc.getParentNode().getParentNode();

                if ( null != parentNode )
                {
                    if ( parentNode.getLocalName().equals( "EncryptedData" ) ) // handle like encDataOnly -> no extern
                                                                               // EncKey
                    {
                        // EncKey inside EncData detected
                        if ( 0 == refElement.size() )
                        {
                            LOG.info( "EncKey inside EncData without referencelist detected." );
                            return true;
                        }
                        else
                        {
                            // how to handle?
                            LOG.error( "EncKey inside EncData with referencelist detected." );
                            return false;
                        }
                    }
                }
            }

        }
        return false;
    }
}
