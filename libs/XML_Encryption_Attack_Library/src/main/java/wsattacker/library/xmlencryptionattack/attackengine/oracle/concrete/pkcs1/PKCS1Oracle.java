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

package wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1;

import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.PKCS1AttackConfig;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.AbstractOracleBehaviour;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.strategy.AbstractPKCS1Strategy;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.TimestampInfo;

/**
 * @author Dennis
 * @version 1.0
 * @created 18-Feb-2014 10:50:04
 */
public class PKCS1Oracle
    extends AOracle
{
    private AbstractPKCS1Strategy m_PKCS1Strategy;

    public PKCS1Oracle( final DetectionReport detectRep, AbstractOracleBehaviour oracleBehave,
                        final ServerSendCommandIF serverSendCmnd, final PKCS1AttackConfig attackCfg )
    {
        if ( null == oracleBehave )
            throw new IllegalArgumentException( "Type of oracle not set!" );

        if ( null == attackCfg )
            throw new IllegalArgumentException( "PKCS1AttackCfg not set" );

        AvoidedDocErrorInfo wrapInfo =
            (AvoidedDocErrorInfo) detectRep.getDetectionInfo( DetectFilterEnum.AVOIDDOCFILTER );
        this.m_OracleBehaviour = oracleBehave;
        this.m_InputFile = detectRep.getRawFile();
        this.m_AvoidedFile = wrapInfo.getAvoidedDocument();
        this.m_AttackPayload = wrapInfo.getOriginalPayInput();
        this.m_ServerCommand = serverSendCmnd;
        this.m_PublicKey = attackCfg.getServerRSAPubKey();
        this.m_AttackedAlgoritm = wrapInfo.getAlgoOfSymmtricBlockCipher();
        this.m_TimestampInfo = (TimestampInfo) detectRep.getDetectionInfo( DetectFilterEnum.TIMESTAMPFILTER );
    }

    @Override
    public OracleResponse[] sendRequests( OracleRequest[] request )
    {
        /*
         * OracleResponse[] oracResps = new OracleResponse[request.length]; String respSever = null; Document
         * errDocument = DomUtilities.createNewDomFromNode(m_AvoidedFile.getDocumentElement()); Element errPayElement =
         * DomUtilities.findCorrespondingElement(errDocument,m_AttackPayload. getAttackPayloadElement());
         * AbstractEncryptionElement dmyAttack = new EncryptedKeyElement(errPayElement); for(int i =
         * 0;request.length>i;i++) {
         * dmyAttack.getCipherDataChild().setEncryptedData(request[i].getEncryptedDataBase64()); // TODO: encdata
         * possible respSever = m_ServerCommand.send(DomUtilities.domToString(errDocument));
         * oracResps[i].setResponse(respSever); }
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
        OracleResponse respMaxScore = null;

        respMaxScore = m_PKCS1Strategy.handleRequest( m_ServerCommand, request );

        numberOfQueries++;

        return respMaxScore;
    }

    public AbstractPKCS1Strategy getPKCS1Strategy()
    {
        return m_PKCS1Strategy;
    }

    public void setPKCS1Strategy( AbstractPKCS1Strategy pkcs1Strategy )
    {
        this.m_PKCS1Strategy = pkcs1Strategy;
    }
}