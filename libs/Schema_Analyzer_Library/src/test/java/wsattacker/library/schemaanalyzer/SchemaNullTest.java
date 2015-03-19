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

import java.util.*;
import javax.xml.namespace.QName;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.schemaanalyzer.TestfilePath.*;

public class SchemaNullTest
{

    private static final String PATH_TO_XML = "src/test/resources/soap11_example_signed_message.xml";

    @Test
    public void simpleTest()
        throws Exception
    {
        Document soap = DomUtilities.readDocument( SOAP11_PATH_TO_SIGNED_XML );

        SchemaAnalyzer sa = new NullSchemaAnalyzer();
        Element envelope = soap.getDocumentElement();

        Set<AnyElementProperties> result = sa.findExpansionPoint( envelope );

        List<Element> childElementList = DomUtilities.getAllChildElements( envelope, true );
        childElementList.add( 0, envelope );
        List<String> fastXPathList = DomUtilities.nodelistToFastXPathList( childElementList );

        assertEquals( childElementList.size(), result.size() );
        assertEquals( fastXPathList.size(), result.size() );

        List<String> contained = new ArrayList<String>();
        for ( AnyElementProperties any : result )
        {
            String fxp = DomUtilities.getFastXPath( any.getDocumentElement() );
            assertTrue( fastXPathList.contains( fxp ) );
            assertTrue( !contained.contains( fxp ) );
            contained.add( fxp );
        }
    }

    @Test
    public void filterTest()
        throws Exception
    {
        Document soap = DomUtilities.readDocument( SOAP11_PATH_TO_EXPANDED_XML );
        Element envelope = soap.getDocumentElement();
        Element header = DomUtilities.getFirstChildElementByNames( envelope, "Header" );
        Element body = DomUtilities.getFirstChildElementByNames( envelope, "Body" );

        SchemaAnalyzer sa = new NullSchemaAnalyzer();

        // Filter...
        List<QName> filterList = new ArrayList<QName>();
        filterList.add( new QName( body.getNamespaceURI(), body.getLocalName(), body.getPrefix() ) );
        sa.setFilterList( filterList );

        Set<AnyElementProperties> result = sa.findExpansionPoint( envelope );

        List<Element> childElementList = new ArrayList<Element>();
        childElementList.add( envelope );
        childElementList.add( header );

        List<String> fastXPathList = DomUtilities.nodelistToFastXPathList( childElementList );

        assertEquals( childElementList.size(), result.size() );
        assertEquals( fastXPathList.size(), result.size() );

        List<String> contained = new ArrayList<String>();
        for ( AnyElementProperties any : result )
        {
            String fxp = DomUtilities.getFastXPath( any.getDocumentElement() );
            assertTrue( fastXPathList.contains( fxp ) );
            assertTrue( !contained.contains( fxp ) );
            contained.add( fxp );
        }
    }
}
