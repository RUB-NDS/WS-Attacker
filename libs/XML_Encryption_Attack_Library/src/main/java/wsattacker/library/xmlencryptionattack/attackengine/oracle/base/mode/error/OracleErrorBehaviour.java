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
package wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.error;

import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.OracleResponseCollector;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.xml.sax.SAXException;
import uk.ac.shef.wit.simmetrics.similaritymetrics.InterfaceStringMetric;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.AbstractOracleBehaviour;

import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;

/**
 * @author dennis
 * @version 1.0
 * @created 18-Feb-2014 10:50:04
 */
public class OracleErrorBehaviour
    extends AbstractOracleBehaviour
{

    private final InterfaceStringMetric m_SimStringStrategy;

    private static final Logger LOG = Logger.getLogger( OracleErrorBehaviour.class );

    public OracleErrorBehaviour( final OracleResponseCollector respTab, final InterfaceStringMetric simStrategy )
    {
        this.m_ErrorResponseTab = respTab;
        this.m_SimStringStrategy = simStrategy;

        if ( null == m_ErrorResponseTab )
        {
            throw new IllegalArgumentException( "ErrorResponseTab not set" );
        }

        if ( null == m_SimStringStrategy )
        {
            throw new IllegalArgumentException( "SimStringStrategy not set" );
        }
    }

    @Override
    public OracleResponse compareServerRespWithUserClassification( OracleResponse resp, AbstractEncryptionElement pay )
    {
        // User Richtscore setzen?...was ist mit unbekannten Serverantworten?
        // => unter einem bestimmten Grenzwert user benachrichtigen? Möglich?
        // TODO: Optimierungsbedarf?
        OracleResponse respMaxScore = null;
        double maxScore = 0.0;
        double tempScore = 0.0;

        if ( m_ErrorResponseTab.isIgnorePayloadResponse() )
        {
            try
            {
                if ( m_ErrorResponseTab.checkIsRequestResponse( resp, pay ) )
                {
                    resp.setResult( OracleResponse.Result.INVALID );
                    return resp;
                }
            }
            catch ( SAXException | XPathExpressionException ex )
            {
                LOG.error(ex);
	    }
        }

        for ( int i = 0; m_ErrorResponseTab.getData().size() > i; i++ )
        {
            tempScore =
                m_SimStringStrategy.getSimilarity( resp.getResponse(),
                                                   m_ErrorResponseTab.getDataEntry( i ).getResponse() );
            if ( tempScore > maxScore )
            {
                respMaxScore = resp;
                respMaxScore.setResult( m_ErrorResponseTab.getDataEntry( i ).getResult() );
                maxScore = tempScore;

                if ( maxScore >= m_ErrorResponseTab.getCompareThreshold() )
                {
                    break;
                }
            }

        }

        // TODO: hinzugefuegt wegen den Angriffen auf Datapower. Jetzt wird VALID/INVALID ausgegeben nur
        // wenn der Wert über dem Threashold liegt
        if ( maxScore < m_ErrorResponseTab.getCompareThreshold() )
        {
            respMaxScore.setResult( OracleResponse.Result.UNDEFINED );
        }

        return respMaxScore;
    }
}
