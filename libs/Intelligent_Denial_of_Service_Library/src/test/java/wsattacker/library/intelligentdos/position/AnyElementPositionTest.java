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
package wsattacker.library.intelligentdos.position;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.schemaanalyzer.AnyElementProperties;
import wsattacker.library.schemaanalyzer.AnyElementPropertiesImpl;
import wsattacker.library.schemaanalyzer.NullAnyElementProperties;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Christian Altmeier
 */
public class AnyElementPositionTest
{

    private static String xmlMessage =
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axis=\"http://axis2.wsattacker\">"
            + "   <soapenv:Header/>" + "   <soapenv:Body>" + "      <axis:reverser>" + "         <!--Optional:-->"
            + "         <axis:toReverse>?</axis:toReverse>" + "      </axis:reverser>" + "   </soapenv:Body>"
            + "</soapenv:Envelope>";

    @Test
    public void createContentTest()
        throws ParserConfigurationException, SAXException
    {
        Document doc = DomUtilities.stringToDom( xmlMessage );

        NodeList childNodes = doc.getDocumentElement().getChildNodes();
        Element element = null;
        for ( int index = 0; index < childNodes.getLength(); index++ )
        {
            Node item = childNodes.item( index );
            if ( "soapenv:Header".equals( item.getNodeName() ) )
            {
                element = (Element) item;
            }
        }

        AnyElementProperties anyElement = new AnyElementPropertiesImpl( element, element );
        AnyElementPosition anyElementPosition = new AnyElementPosition( xmlMessage, anyElement );

        assertThat( anyElementPosition.createPlaceholder( PayloadPosition.ELEMENT ),
                    is( "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axis=\"http://axis2.wsattacker\">"
                        + "   <soapenv:Header>$$PAYLOADELEMENT$$</soapenv:Header>"
                        + "   <soapenv:Body>"
                        + "      <axis:reverser>"
                        + "         <!--Optional:-->"
                        + "         <axis:toReverse>?</axis:toReverse>"
                        + "      </axis:reverser>"
                        + "   </soapenv:Body>" + "</soapenv:Envelope>" ) );
    }

    @Test
    public void equalsTest()
        throws ParserConfigurationException
    {
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
        // root elements
        Document doc = docBuilder.newDocument();
        Element element = doc.createElementNS( "http://schemas.xmlsoap.org/soap/envelope/", "soapenv:Header" );
        Element element2 = doc.createElementNS( "http://schemas.xmlsoap.org/soap/envelope/", "soapenv:Header" );
        Element element3 = doc.createElementNS( "http://schemas.xmlsoap.org/soap/envelope/", "soapenv:Body" );

        AnyElementProperties anyElement = new NullAnyElementProperties( element );
        AnyElementPosition anyElementPosition = new AnyElementPosition( xmlMessage, anyElement );

        assertThat( anyElementPosition.equals( null ), is( Boolean.FALSE ) );
        assertThat( anyElementPosition.equals( anyElementPosition ), is( Boolean.TRUE ) );
        assertThat( anyElementPosition.equals( Integer.valueOf( 1 ) ), is( Boolean.FALSE ) );

        AnyElementProperties anyElement2 = new NullAnyElementProperties( element );
        AnyElementPosition anyElementEQ = new AnyElementPosition( xmlMessage, anyElement2 );
        assertThat( anyElementPosition.equals( anyElementEQ ), is( Boolean.TRUE ) );

        AnyElementProperties anyElement3 = new NullAnyElementProperties( element2 );
        AnyElementPosition anyElementEQ2 = new AnyElementPosition( xmlMessage, anyElement3 );
        assertThat( anyElementPosition.equals( anyElementEQ2 ), is( Boolean.TRUE ) );

        AnyElementProperties anyElement4 = new NullAnyElementProperties( element3 );
        AnyElementPosition anyElementNEW = new AnyElementPosition( xmlMessage, anyElement4 );
        assertThat( anyElementPosition.equals( anyElementNEW ), is( Boolean.FALSE ) );
    }

}
