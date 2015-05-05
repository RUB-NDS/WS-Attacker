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
import java.util.Random;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;
import wsattacker.library.xmlencryptionattack.util.HelperFunctions;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class AvoidedDocErrorFilter
    extends AbstractDetectionFilter
{
    public enum ErrorGenerator
    {
        NO_RANDOM, RANDOM
    };

    // public static final int CHANGE_COMPLETE_PAYLOAD = -1;

    private final ErrorGenerator m_ErrorGen = ErrorGenerator.RANDOM;

    private AbstractEncryptionElement m_PayLoadInput = null;

    // private int m_BytePosToChange;

    public AvoidedDocErrorFilter( DetectFilterEnum filterType )
    {
        this.mFilterType = filterType;
        this.m_OutputFilter = new AvoidedDocErrorInfo( filterType );
    }

    @Override
    public AbstractDetectionInfo process()
    {
        String newCipherVal = null;

        if ( null == m_PayLoadInput )
            throw new IllegalArgumentException( "payload input not set" );

        if ( null == m_PayLoadInput.getAttackProperties().getAttackPayloadElement() )
            throw new IllegalArgumentException(
                                                "no attack payload is set => first you have to generate an attack message for payload" );

        Element attackPay = m_PayLoadInput.getAttackProperties().getAttackPayloadElement();
        Document errDocument = DomUtilities.createNewDomFromNode( attackPay.getOwnerDocument().getDocumentElement() );
        Element errPayElement = DomUtilities.findCorrespondingElement( errDocument, attackPay );

        // no deep = true because of wrapping other encrypted element in this element => more than 1 element will be
        // found
        List<Element> cipherDataErrPay = DomUtilities.findChildren( errPayElement, "CipherData", URI_NS_ENC );

        if ( 1 != cipherDataErrPay.size() )
        {
            throw new IllegalArgumentException(
                                                "Encrypted element has not one CipherData-Element => should never happen" );
        }

        List<Element> cipherValErrPay =
            DomUtilities.findChildren( cipherDataErrPay.get( 0 ), "CipherValue", URI_NS_ENC );

        if ( 1 != cipherValErrPay.size() )
        {
            throw new IllegalArgumentException(
                                                "Encrypted element has not one CipherValue-Element => should never happen" );
        }
        switch ( m_ErrorGen )
        {
            case RANDOM:
                newCipherVal = generateRandomPayload();
                break;
            case NO_RANDOM:
                newCipherVal = generateNoRandomPayload();
                break;
        }

        cipherValErrPay.get( 0 ).setTextContent( newCipherVal );

        ( (AvoidedDocErrorInfo) m_OutputFilter ).setOriginalPayInput( m_PayLoadInput );
        ( (AvoidedDocErrorInfo) m_OutputFilter ).setErrorPayOutput( errPayElement );
        ( (AvoidedDocErrorInfo) m_OutputFilter ).setErrorDocument( errDocument );
        ( (AvoidedDocErrorInfo) m_OutputFilter ).setAvoidedDocument( m_InputFilter );

        return ( (AvoidedDocErrorInfo) m_OutputFilter );
    }

    private String generateRandomPayload()
    {
        Random r = new Random();
        CryptoConstants.Algorithm algo = null; // symmetric algo !!!
        byte[] randomBytes = null;

        if ( m_PayLoadInput instanceof EncryptedKeyElement ) // encryptedkey has at least one encData!!!!
                                                             // could not work if no encData!!
        {
            EncryptedDataElement encData = null;
            encData = HelperFunctions.getEncDataOfEncryptedKey( (EncryptedKeyElement) m_PayLoadInput );
            algo = CryptoConstants.getAlgorithm( encData.getEncryptionMethod() );
            randomBytes = new byte[algo.KEY_SIZE];

        }
        else
        {
            algo = CryptoConstants.getAlgorithm( m_PayLoadInput.getEncryptionMethod() );
            randomBytes = new byte[algo.BLOCK_SIZE * 2];
        }
        ( (AvoidedDocErrorInfo) m_OutputFilter ).setAlgoOfSymmtricBlockCipher( algo );

        r.nextBytes( randomBytes );

        return Base64.encodeBytes( randomBytes );
    }

    private String generateNoRandomPayload()
    {
        throw new UnsupportedOperationException( "Not supported yet." ); // To change body of generated methods, choose
                                                                         // Tools | Templates.
    }

    public void setPayloadInput( AbstractEncryptionElement input )
    {
        this.m_PayLoadInput = input;
    }

    public AbstractEncryptionElement getPayloadInput()
    {
        return m_PayLoadInput;
    }

}