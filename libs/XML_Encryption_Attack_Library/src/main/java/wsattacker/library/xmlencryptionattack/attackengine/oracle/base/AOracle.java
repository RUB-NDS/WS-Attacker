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
package wsattacker.library.xmlencryptionattack.attackengine.oracle.base;

import java.security.interfaces.RSAPublicKey;
import org.w3c.dom.Document;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.AbstractOracleBehaviour;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.TimestampInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.timestampelement.TimestampBase;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants.Algorithm;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;

/**
 * Oracle used to attack a Web Service The oracle is used as follows: First, the attacker sends different requests to
 * the oracle. Oracle responds with the Responses. Afterwards, the attacker can analyze the responses, decide which of
 * them are valid/invalid, and save this property in the oracle. Finally, the attacker can execute the attack using the
 * queryOracle function. Feel free to modify this class and its methods.
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public abstract class AOracle
{

    protected Document m_InputFile;

    protected Document m_AvoidedFile;

    protected AbstractEncryptionElement m_AttackPayload;

    protected ServerSendCommandIF m_ServerCommand;

    protected Algorithm m_AttackedAlgoritm;

    protected TimestampInfo m_TimestampInfo = null;

    protected AbstractOracleBehaviour m_OracleBehaviour;

    // protected String m_AttackPartBeforeCipherVal;
    // protected String m_AttackPartAfterCipherVal;
    /*
     * number of queries issued to oracle
     */
    protected long numberOfQueries;

    /**
     * public key used by the Bleichenbacher attack to generate new queries (by the CBC attack this variable can be
     * null)
     */
    protected RSAPublicKey m_PublicKey;

    /**
     * Sends requests to the oracle (use the VectorGenerator class for this purpose)
     * 
     * @param request
     * @return
     */
    public abstract OracleResponse[] sendRequests( OracleRequest[] request );

    /**
     * Set the response validity.
     * 
     * @param response
     * @param result
     */
    public abstract void setResponseValidity( OracleResponse response, OracleResponse.Result result );

    /**
     * This function should be used during the attack. It takes a request and sends it to the server and evaluates, if
     * the request was valid or invalid.
     * 
     * @param request
     * @return
     */
    public abstract OracleResponse queryOracle( OracleRequest request );

    /**
     * sets the number of queries back to its original value
     */
    public void resetNumberOfQueries()
    {
        numberOfQueries = 0;
    }

    /**
     * @return
     */
    public long getNumberOfQueries()
    {
        return numberOfQueries;
    }

    public Document getInputFile()
    {
        return m_InputFile;
    }

    public void setInputFile( Document inputFile )
    {
        this.m_InputFile = inputFile;
    }

    public Document getAvoidedFile()
    {
        return m_AvoidedFile;
    }

    public void setAvoidedFile( Document avoidedFile )
    {
        this.m_AvoidedFile = avoidedFile;
    }

    public AbstractEncryptionElement getAttackPayload()
    {
        return m_AttackPayload;
    }

    public CryptoConstants.Algorithm getAttackedAlgoritm()
    {
        return m_AttackedAlgoritm;
    }

    public void setAttackedAlgoritm( CryptoConstants.Algorithm attackedAlgoritm )
    {
        this.m_AttackedAlgoritm = attackedAlgoritm;
    }

    public RSAPublicKey getPublicKey()
    {
        return m_PublicKey;
    }

    public void handleTimeStamp( Document attackDoc )
        throws InvalidPayloadException
    {
        if ( null != m_TimestampInfo )
        {
            TimestampBase timestamp = m_TimestampInfo.getTimestamp();
            if ( null != timestamp && null != timestamp.getDetectionPayElement() )
            {
                timestamp.updateTimeStamp( attackDoc );
            }
        }

    }

    public AbstractOracleBehaviour getOracleBehaviour()
    {
        return m_OracleBehaviour;
    }
}
