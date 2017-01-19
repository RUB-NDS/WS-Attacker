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
package wsattacker.library.intelligentdos.dos;

import java.io.IOException;
import javax.xml.parsers.ParserConfigurationException;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.testhelper.IDoSTestHelper;

/**
 * @author chal
 */
public class PayloadPositionTest
{

    // public static String replace( Document document )
    // {
    // String domToString = DomUtilities.domToString( document );
    // domToString = domToString.replace( "PAYLOAD=\"PAYLOAD\"",
    // PLACEHOLDER_ATTRIBUTE );
    // domToString = domToString.replace( "<PAYLOADELEMENT/>",
    // PLACEHOLDER_ELEMENT );
    // return domToString;
    // }

    @Test
    public void testCreatePlaceholderELEMENT()
        throws ParserConfigurationException, SAXException, IOException
    {
        PayloadPosition element = PayloadPosition.ELEMENT;

        Document document = IDoSTestHelper.createTestDocument();
        NodeList nl = document.getElementsByTagName( "soapenv:Header" );
        Element c = (Element) nl.item( 0 );

        element.createPlaceholder( document, c );

        nl = document.getElementsByTagName( "PAYLOADELEMENT" );
        assertThat( nl.getLength(), is( 1 ) );
    }

    @Test
    public void testCreatePlaceholderATTRIBUTE()
        throws ParserConfigurationException, SAXException, IOException
    {
        PayloadPosition element = PayloadPosition.ATTRIBUTE;

        Document document = IDoSTestHelper.createTestDocument();
        NodeList nl = document.getElementsByTagName( "soapenv:Header" );
        Element c = (Element) nl.item( 0 );

        element.createPlaceholder( document, c );

        nl = document.getElementsByTagName( "soapenv:Header" );
        assertThat( nl.getLength(), is( 1 ) );
        c = (Element) nl.item( 0 );
        String attribute = c.getAttribute( "PAYLOAD" );
        assertThat( attribute, is( "PAYLOAD" ) );
    }

    @Test
    public void testCreateAndReplacePlaceholderELEMENT()
        throws ParserConfigurationException, SAXException, IOException
    {
        PayloadPosition element = PayloadPosition.ELEMENT;

        Document document = IDoSTestHelper.createTestDocument();
        NodeList nl = document.getElementsByTagName( "soapenv:Header" );
        Element c = (Element) nl.item( 0 );
        String createAndReplacePlaceholder = element.createAndReplacePlaceholder( document, c );
        assertThat( createAndReplacePlaceholder, containsString( "<soapenv:Header>$$PAYLOADELEMENT$$</soapenv:Header>" ) );

        document = IDoSTestHelper.createTestDocument();
        nl = document.getElementsByTagName( "soapenv:Body" );
        c = (Element) nl.item( 0 );
        createAndReplacePlaceholder = element.createAndReplacePlaceholder( document, c );
        assertThat( createAndReplacePlaceholder, containsString( "$$PAYLOADELEMENT$$</soapenv:Body>" ) );
    }

    @Test
    public void testCreateAndReplacePlaceholderATTRIBUTE()
        throws ParserConfigurationException, SAXException, IOException
    {
        PayloadPosition element = PayloadPosition.ATTRIBUTE;

        Document document = IDoSTestHelper.createTestDocument();
        NodeList nl = document.getElementsByTagName( "soapenv:Header" );
        Element c = (Element) nl.item( 0 );
        String createAndReplacePlaceholder = element.createAndReplacePlaceholder( document, c );
        assertThat( createAndReplacePlaceholder, containsString( "<soapenv:Header $$PAYLOADATTR$$/>" ) );

        document = IDoSTestHelper.createTestDocument();
        nl = document.getElementsByTagName( "soapenv:Body" );
        c = (Element) nl.item( 0 );
        createAndReplacePlaceholder = element.createAndReplacePlaceholder( document, c );
        assertThat( createAndReplacePlaceholder, containsString( "<soapenv:Body $$PAYLOADATTR$$>" ) );
    }

    @Test
    public void testReplacePlaceholder()
    {
        String replacePlaceholder = PayloadPosition.ELEMENT.replacePlaceholder( ">$$PAYLOADELEMENT$$<", "def" );
        assertThat( replacePlaceholder, is( ">def<" ) );

        replacePlaceholder = PayloadPosition.ATTRIBUTE.replacePlaceholder( "<aa $$PAYLOADATTR$$>", "def" );
        assertThat( replacePlaceholder, is( "<aa def>" ) );
    }

    @Test
    public void testReplace()
        throws ParserConfigurationException, SAXException, IOException
    {
        Document document = IDoSTestHelper.createTestDocument();
        NodeList nl = document.getElementsByTagName( "soapenv:Header" );
        Element c = (Element) nl.item( 0 );
        PayloadPosition.ELEMENT.createPlaceholder( document, c );
        PayloadPosition.ATTRIBUTE.createPlaceholder( document, c );

        String replace = PayloadPosition.replace( document );
        assertThat( replace, containsString( "<soapenv:Header $$PAYLOADATTR$$>$$PAYLOADELEMENT$$</soapenv:Header>" ) );
    }
}
