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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import org.junit.Ignore;
import org.junit.Test;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.dos.XmlOverlongNames.For;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.testhelper.IDoSTestHelper;

/**
 * @author Christian Altmeier
 */
public class XmlOverlongNamesTest
{

    private final XmlOverlongNames xmlOverlongNames = new XmlOverlongNames();

    @Test
    public void nameTest()
    {
        assertThat( xmlOverlongNames.getName(), is( "XmlOverlongNames" ) );
    }

    @Test
    public void getParamTest()
    {
        For[] overlongNamesFor = xmlOverlongNames.getOverlongNamesFor();
        assertThat( overlongNamesFor.length, is( 3 ) );
        assertThat( overlongNamesFor[0], is( For.ElementName ) );
        assertThat( overlongNamesFor[1], is( For.AttributeName ) );
        assertThat( overlongNamesFor[2], is( For.AttributeValue ) );

        IterateModel lengthOfStringsIterator = xmlOverlongNames.getLengthOfStringsIterator();
        assertNotNull( lengthOfStringsIterator );

        IterateModel numberOfElementsIterator = xmlOverlongNames.getNumberOfElementsIterator();
        assertNotNull( numberOfElementsIterator );
    }

    @Test
    public void setParamForTest()
    {
        try
        {
            xmlOverlongNames.setOverlongNamesFor( null );
            fail();
        }
        catch ( IllegalArgumentException e )
        {
            // OK
        }

        try
        {
            xmlOverlongNames.setOverlongNamesFor( new For[0] );
            fail();
        }
        catch ( IllegalArgumentException e )
        {
            // OK
        }

        try
        {
            xmlOverlongNames.setLengthOfStringsIterator( null );
            fail();
        }
        catch ( IllegalArgumentException e )
        {
            // OK
        }

        try
        {
            xmlOverlongNames.setNumberOfElementsIterator( null );
            fail();
        }
        catch ( IllegalArgumentException e )
        {
            // OK
        }

    }

    @Test
    public void hasFurther()
    {
        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
    }

    @Test
    public void oneParam()
    {
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.ElementName } );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();
        assertThat( xmlOverlongNames.hasFurtherParams(), is( false ) );

        // coverage
        xmlOverlongNames.nextParam();
    }

    @Test
    public void twoTwoTwo()
    {
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.ElementName, For.AttributeName } );

        for ( int i = 0; i < 8; i++ )
        {
            assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
            xmlOverlongNames.nextParam();
        }

        assertThat( xmlOverlongNames.hasFurtherParams(), is( false ) );
    }

    @Test( expected = IllegalArgumentException.class )
    public void notAllowedPayloadPosition()
    {
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.ElementName, For.AttributeName } );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        xmlOverlongNames.getTamperedRequest( "", null );
    }

    @Test
    public void tamperedElementName()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 8 ).stopAt( 10 ).setIncrement( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 1 ).stopAt( 1 ).setIncrement( 1 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.ElementName } );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        String tampered = "><AAAAAAAA>value</AAAAAAAA></";
        assertThat( xmlOverlongNames.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        tampered = "><AAAAAAAAAA>value</AAAAAAAAAA></";
        assertThat( xmlOverlongNames.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( false ) );
    }

    @Test
    public void tamperedAttributeName()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 8 ).stopAt( 10 ).setIncrement( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 1 ).stopAt( 1 ).setIncrement( 1 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.AttributeName } );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        String tampered = "><attackElement BBBBBBBB=\"test\">value</attackElement></";
        assertThat( xmlOverlongNames.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        tampered = "><attackElement BBBBBBBBBB=\"test\">value</attackElement></";
        assertThat( xmlOverlongNames.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( false ) );
    }

    @Test
    public void tamperedAttributeValue()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 8 ).stopAt( 10 ).setIncrement( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 1 ).stopAt( 1 ).setIncrement( 1 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.AttributeValue } );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        String tampered = "><attackElement long=\"CCCCCCCC\">value</attackElement></";
        assertThat( xmlOverlongNames.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        tampered = "><attackElement long=\"CCCCCCCCCC\">value</attackElement></";
        assertThat( xmlOverlongNames.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untamperedElementName()
        throws ParserConfigurationException
    {
        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 8 ).stopAt( 10 ).setIncrement( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 1 ).stopAt( 2 ).setIncrement( 1 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.ElementName } );

        // 1 - 8
        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        String tamperedRequest = xmlOverlongNames.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = xmlOverlongNames.getUntamperedRequest( xml, payloadPosition );

        String referece = "><!-- ccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        // 1 - 10
        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        tamperedRequest = xmlOverlongNames.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlOverlongNames.getUntamperedRequest( xml, payloadPosition );

        referece = "><!-- ccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        // 2 - 8
        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        tamperedRequest = xmlOverlongNames.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlOverlongNames.getUntamperedRequest( xml, payloadPosition );

        referece = "><!-- ccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        // 2 - 10
        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        tamperedRequest = xmlOverlongNames.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlOverlongNames.getUntamperedRequest( xml, payloadPosition );

        referece = "><!-- ccccccccccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untamperedAttributeName()
        throws ParserConfigurationException
    {
        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 8 ).stopAt( 10 ).setIncrement( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 1 ).stopAt( 1 ).setIncrement( 1 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.AttributeName } );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        String tamperedRequest = xmlOverlongNames.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = xmlOverlongNames.getUntamperedRequest( xml, payloadPosition );

        String referece = "><!-- ccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        tamperedRequest = xmlOverlongNames.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlOverlongNames.getUntamperedRequest( xml, payloadPosition );

        referece = "><!-- ccccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untamperedAttributeValue()
        throws ParserConfigurationException
    {
        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        // length string
        IterateModel iterateModel = IterateModel.custom().startAt( 8 ).stopAt( 10 ).setIncrement( 2 ).build();
        xmlOverlongNames.setLengthOfStringsIterator( iterateModel );
        // number of elements
        iterateModel = IterateModel.custom().startAt( 1 ).stopAt( 1 ).setIncrement( 1 ).build();
        xmlOverlongNames.setNumberOfElementsIterator( iterateModel );

        xmlOverlongNames.setOverlongNamesFor( new For[] { For.AttributeValue } );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        String tamperedRequest = xmlOverlongNames.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = xmlOverlongNames.getUntamperedRequest( xml, payloadPosition );

        String referece = "><!-- ccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( true ) );
        xmlOverlongNames.nextParam();

        tamperedRequest = xmlOverlongNames.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlOverlongNames.getUntamperedRequest( xml, payloadPosition );

        referece = "><!-- ccccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlOverlongNames.hasFurtherParams(), is( false ) );
    }

    @Ignore
    public void hashCodeTest()
    {
        assertThat( xmlOverlongNames.hashCode(), is( 42 ) );
    }

    @Test
    public void equalsTest()
    {
        assertThat( xmlOverlongNames.equals( null ), is( false ) );
        assertThat( xmlOverlongNames.equals( xmlOverlongNames ), is( true ) );

        CoerciveParsing coerciveParsing = new CoerciveParsing();
        assertThat( xmlOverlongNames.equals( coerciveParsing ), is( false ) );

        XmlOverlongNames o_this = new XmlOverlongNames();
        o_this.nextParam();
        XmlOverlongNames o_that = new XmlOverlongNames();
        o_that.nextParam();
        assertThat( o_this.equals( o_that ), is( true ) );

        o_this = new XmlOverlongNames();
        o_this.nextParam();
        o_that = new XmlOverlongNames();
        o_that.setOverlongNamesFor( new For[] { For.AttributeValue } );
        o_that.nextParam();
        assertThat( o_this.equals( o_that ), is( false ) );
    }
}
