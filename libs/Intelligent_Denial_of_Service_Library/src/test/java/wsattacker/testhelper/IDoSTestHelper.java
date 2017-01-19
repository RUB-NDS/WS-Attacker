/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.testhelper;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.StringReader;
import javax.xml.XMLConstants;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import wsattacker.library.intelligentdos.IntelligentDoSLibrary;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;

/**
 * @author Christian Altmeier
 */
public class IDoSTestHelper
{

    public static final String template =
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axis=\"http://axis2.wsattacker\">"
            + "<soapenv:Header></soapenv:Header>"
            + "<soapenv:Body><axis:reverser><axis:aFunction>Lorem Ipsum</axis:aFunction></axis:reverser></soapenv:Body>"
            + "</soapenv:Envelope>";

    public static Document createTestDocument()
        throws ParserConfigurationException, SAXException, IOException
    {
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        docFactory.setFeature( XMLConstants.FEATURE_SECURE_PROCESSING, true );
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

        InputSource is = new InputSource( new StringReader( template ) );
        Document d = docBuilder.parse( is );

        return d;
    }

    public static String createTestString( PayloadPosition payloadPosition )
        throws ParserConfigurationException
    {
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        docFactory.setFeature( XMLConstants.FEATURE_SECURE_PROCESSING, true );
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

        InputSource is = new InputSource( new StringReader( template ) );
        try
        {
            Document d = docBuilder.parse( is );
            NodeList nl = d.getElementsByTagName( "soapenv:Header" );
            Element c = (Element) nl.item( 0 );

            String xml = payloadPosition.createAndReplacePlaceholder( d, c );

            return xml;
        }
        catch ( SAXException e )
        {
            e.printStackTrace();
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }

        // root elements
        Document doc = docBuilder.newDocument();
        Element rootElement = doc.createElement( "tampered" );
        doc.appendChild( rootElement );

        String xml = payloadPosition.createAndReplacePlaceholder( doc, rootElement );
        return xml;
    }

    public static void iterate( MetricOracle metricOracle, DoSAttack[] attacks, IntelligentDoSLibrary impl )
    {
        int count = 0;

        // first attack to send (UTR)
        assertThat( impl.hasFurtherAttack(), is( true ) );
        AttackModel attackModel = impl.nextAttack();

        for ( DoSAttack doSAttack : attacks )
        {
            assertThat( attackModel.getRequestType(), is( RequestType.UNTAMPERED ) );
            String doSName = doSAttack.getName();
            assertThat( attackModel.getDoSAttack().getName(), is( doSName ) );
            if ( count == 0 )
            {
                assertThat( attackModel.getServerRecoveryBeforeSend(), is( 0 ) );
            }
            else
            {
                assertThat( attackModel.getServerRecoveryBeforeSend(), is( 1000 ) );
            }
            metricOracle.createMetric( attackModel );
            impl.update( attackModel );
            assertThat( impl.hasFurtherAttack(), is( true ) );

            attackModel = itr( impl, doSName, metricOracle );

            count++;
        }
    }

    private static AttackModel itr( IntelligentDoSLibrary library, String doSString, MetricOracle metricOracle )
    {
        AttackModel attackModel = null;
        while ( library.hasFurtherAttack()
            && doSString.equals( ( attackModel = library.nextAttack() ).getDoSAttack().getName() ) )
        {
            // System.out.println(count + ": " + attackModel);
            // response from the server
            metricOracle.createMetric( attackModel );
            library.update( attackModel );
        }

        return attackModel;
    }
}
