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
import wsattacker.testhelper.IDoSTestHelper;

/**
 * @author Christian Altmeier
 */
public class XmlAttributeCountTest
{
    private final XmlAttributeCount xmlAttributeCount = new XmlAttributeCount();

    @Test
    public void nameTest()
    {
        assertThat( xmlAttributeCount.getName(), is( "XmlAttributeCount" ) );
    }

    @Test
    public void hasFurther()
    {
        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
    }

    @Test
    public void oneIteration()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlAttributeCount.setNumberOfAttributesIterator( iterateModel );
        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();
        assertThat( xmlAttributeCount.hasFurtherParams(), is( false ) );
    }

    @Test
    public void twoTwo()
    {
        // two number of attributes
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        xmlAttributeCount.setNumberOfAttributesIterator( iterateModel );
        // use namespace: true and false
        xmlAttributeCount.setNames( new String[] { "a", "b" } );

        for ( int i = 0; i < 4; i++ )
        {
            assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
            xmlAttributeCount.nextParam();
        }

        assertThat( xmlAttributeCount.hasFurtherParams(), is( false ) );
    }

    @Test( expected = IllegalArgumentException.class )
    public void notAllowedPayloadPosition()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlAttributeCount.setNumberOfAttributesIterator( iterateModel );
        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        xmlAttributeCount.getTamperedRequest( "", null );
    }

    @Test( expected = IllegalArgumentException.class )
    public void nullPayloadPosition()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlAttributeCount.setNumberOfAttributesIterator( iterateModel );
        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        xmlAttributeCount.getTamperedRequest( "", null );
    }

    @Test
    public void tamperedATTRIBUTE()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ATTRIBUTE;
        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 12 ).setIncrement( 10 ).build();

        xmlAttributeCount.setNumberOfAttributesIterator( iterateModel );
        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        String tampered = " a0=\"0\" a1=\"1\" />";
        assertThat( xmlAttributeCount.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        tampered =
            " a0=\"0\" a1=\"1\" a2=\"2\" a3=\"3\" a4=\"4\" a5=\"5\" "
                + "a6=\"6\" a7=\"7\" a8=\"8\" a9=\"9\" a10=\"10\" a11=\"11\" />";
        assertThat( xmlAttributeCount.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlAttributeCount.hasFurtherParams(), is( false ) );
    }

    @Test
    public void tamperedELEMENT()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;
        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();

        xmlAttributeCount.setNumberOfAttributesIterator( iterateModel );
        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        String tampered = "><attackElement a0=\"0\" a1=\"1\" /></";
        assertThat( xmlAttributeCount.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        tampered = "><attackElement a0=\"0\" a1=\"1\" a2=\"2\" a3=\"3\" /></";
        assertThat( xmlAttributeCount.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlAttributeCount.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untamperedATTRIBUTE()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ATTRIBUTE;
        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 4 ).stopAt( 12 ).setIncrement( 8 ).build();

        xmlAttributeCount.setNumberOfAttributesIterator( iterateModel );
        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        String tamperedRequest = xmlAttributeCount.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = xmlAttributeCount.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertThat( untamperedRequest, startsWith( "<!-- ccccccccccccccccccc --><" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        tamperedRequest = xmlAttributeCount.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlAttributeCount.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertThat( untamperedRequest,
                    startsWith( "<!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --><" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlAttributeCount.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untamperedELEMENT()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;
        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 4 ).stopAt( 12 ).setIncrement( 8 ).build();

        xmlAttributeCount.setNumberOfAttributesIterator( iterateModel );
        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        String tamperedRequest = xmlAttributeCount.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = xmlAttributeCount.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertThat( untamperedRequest, containsString( "><!-- cccccccccccccccccccccccccccccccccccc --></" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlAttributeCount.hasFurtherParams(), is( true ) );
        xmlAttributeCount.nextParam();

        tamperedRequest = xmlAttributeCount.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlAttributeCount.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertThat( untamperedRequest,
                    containsString( "><!-- cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --></" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlAttributeCount.hasFurtherParams(), is( false ) );
    }

    @Test
    public void minimalTest()
        throws ParserConfigurationException
    {
        xmlAttributeCount.nextParam();

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;
        String xml = IDoSTestHelper.createTestString( payloadPosition );

        DoSAttack minimal = xmlAttributeCount.minimal();
        String tamperedRequest = minimal.getTamperedRequest( xml, payloadPosition );

        assertThat( tamperedRequest, containsString( "><attackElement a0=\"0\" a1=\"1\" /><" ) );
    }
}
