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

package wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.xpath.XPathExpressionException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import uk.ac.shef.wit.simmetrics.similaritymetrics.InterfaceStringMetric;
import wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory.SimStringStrategy;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 */
@XmlAccessorType( XmlAccessType.FIELD )
@XmlRootElement( name = "OracleResponseCollector" )
public class OracleResponseCollector
{
    @XmlElement( name = "OracleResponse", type = OracleResponse.class )
    private List<OracleResponse> m_OracleResponseMap = new ArrayList<OracleResponse>();

    private double m_CompareThreshold;

    private boolean m_IsIgnorePayloadResponse;

    public OracleResponseCollector( List<OracleResponse> respList )
    {
        this.m_OracleResponseMap = respList;
        this.m_CompareThreshold = 1.0;
        this.m_IsIgnorePayloadResponse = false;
    }

    public OracleResponseCollector()
    {
        this.m_CompareThreshold = 1.0;
        this.m_IsIgnorePayloadResponse = false;
    }

    public List<OracleResponse> getData()
    {
        return m_OracleResponseMap;
    }

    public OracleResponse getDataEntry( int i )
    {
        return m_OracleResponseMap.get( i );
    }

    public boolean add( OracleResponse data )
    {
        InterfaceStringMetric simStringStrategy =
            SimStringStrategyFactory.createSimStringStrategy( SimStringStrategy.DICE_COEFF );
        double tempScore = 0.0;
        for ( int i = 0; m_OracleResponseMap.size() > i; i++ )
        {
            tempScore = simStringStrategy.getSimilarity( data.getResponse(), getDataEntry( i ).getResponse() );

            if ( m_CompareThreshold <= tempScore )
            {
                return false;
            }
        }
        m_OracleResponseMap.add( data );
        return true;
    }

    public boolean checkIsRequestResponse( OracleResponse oresponse, AbstractEncryptionElement pay )
        throws SAXException, XPathExpressionException
    {
        Document responseDoc = DomUtilities.stringToDom( oresponse.getResponse() );

        List<Element> encPayList =
            (List<Element>) DomUtilities.evaluateXPath( responseDoc, "//*[local-name()='EncryptedData' "
                + "and namespace-uri()='" + URI_NS_ENC + "']" );
        for ( Element payEl : encPayList )
        {
            if ( pay.getEncryptedElement().isEqualNode( payEl ) )
                return true;
        }

        return false;
    }

    public boolean isIgnorePayloadResponse()
    {
        return m_IsIgnorePayloadResponse;
    }

    public void setIsIgnorePayloadResponse( boolean isIgnorePayloadResponse )
    {
        this.m_IsIgnorePayloadResponse = isIgnorePayloadResponse;
    }

    public double getCompareThreshold()
    {
        return m_CompareThreshold;
    }

    public void setCompareThreshold( double compareThreshold )
    {
        this.m_CompareThreshold = compareThreshold;
    }

    public void setData( List<OracleResponse> respList )
    {
        this.m_OracleResponseMap = respList;
    }
}
