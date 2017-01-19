/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
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
package wsattacker.library.schemaanalyzer;

import java.io.IOException;
import java.util.List;
import javax.xml.xpath.XPathExpressionException;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import static wsattacker.library.xmlutilities.dom.DomUtilities.evaluateXPath;

/**
 * @author dev
 */
public class AnyElementPropertiesImplTest
{

    public AnyElementPropertiesImplTest()
    {
    }

    @Test
    public void testGetProcessContentsAttribute()
        throws Exception
    {

        AnyElementProperties anyProperties = getSoapBody11AnyElementProperties();
        assertEquals( "lax", anyProperties.getProcessContentsAttribute() );
    }

    private AnyElementPropertiesImpl getSoapBody11AnyElementProperties()
        throws IOException, XPathExpressionException, SAXException
    {
        final Document schemaXmldsig = SchemaAnalyzerFactory.getSchemaDocument( "soap11.xsd" );
        assertThat( schemaXmldsig.getDocumentElement().getLocalName(), is( "schema" ) );
        final String xpath = "/xs:schema/xs:complexType[@name='Body']/xs:sequence/xs:any";
        final List<? extends Node> evaluatedXPath = evaluateXPath( schemaXmldsig, xpath );
        assertThat( evaluatedXPath, hasSize( 1 ) );
        Element anyElement = (Element) evaluatedXPath.get( 0 );
        AnyElementPropertiesImpl anyProperties = new AnyElementPropertiesImpl( anyElement, null );
        return anyProperties;
    }

    @Test
    public void testGetNamespaceAttributeValue()
        throws Exception
    {
        AnyElementPropertiesImpl anyProperties = getSoapBody11AnyElementProperties();
        assertEquals( "##any", anyProperties.getNamespaceAttributeValue() );
    }

    @Test
    public void testIsInSequence()
        throws Exception
    {
        AnyElementPropertiesImpl anyProperties = getSoapBody11AnyElementProperties();
        // todo: diese methode existiert doch nicht ??? wie kann man die testen?
        // assertTrue( anyProperties.isInSequence() );
    }

    private AnyElementPropertiesImpl getEmbeddedTypeAnyElementProperties()
        throws IOException, XPathExpressionException, SAXException
    {
        final Document schemaXmldsig = SchemaAnalyzerFactory.getSchemaDocument( "wssec-1.0.xsd" );
        assertThat( schemaXmldsig.getDocumentElement().getLocalName(), is( "schema" ) );
        final String xpath = "/xsd:schema/xsd:complexType[@name='EmbeddedType']/xsd:choice/xsd:any";
        final List<? extends Node> evaluatedXPath = evaluateXPath( schemaXmldsig, xpath );
        assertThat( evaluatedXPath, hasSize( 1 ) );
        Element anyElement = (Element) evaluatedXPath.get( 0 );
        AnyElementPropertiesImpl anyProperties = new AnyElementPropertiesImpl( anyElement, null );
        return anyProperties;
    }

    @Test
    public void testIsNotInSequence()
        throws Exception
    {
        AnyElementPropertiesImpl anyProperties = getEmbeddedTypeAnyElementProperties();
        // todo: diese methode existiert doch nicht ???
        // assertFalse( anyProperties.isInSequence() );
    }

}
