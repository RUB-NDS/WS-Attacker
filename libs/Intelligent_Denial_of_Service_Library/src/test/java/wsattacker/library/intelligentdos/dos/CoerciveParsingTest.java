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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;

import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.testhelper.IDoSTestHelper;

/**
 * @author Christian Altmeier
 */
public class CoerciveParsingTest
{

    private final CoerciveParsing coerciveParsing = new CoerciveParsing();

    @Test
    public void hasFurther()
    {
        assertThat( coerciveParsing.hasFurtherParams(), is( true ) );
    }

    @Test
    public void oneParam()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        coerciveParsing.setNumberOfTagsIterator( iterateModel );
        assertThat( coerciveParsing.hasFurtherParams(), is( true ) );
        coerciveParsing.nextParam();
        assertThat( coerciveParsing.hasFurtherParams(), is( false ) );
    }

    @Test( expected = IllegalArgumentException.class )
    public void notAllowedPayloadPosition()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        coerciveParsing.setNumberOfTagsIterator( iterateModel );
        assertThat( coerciveParsing.hasFurtherParams(), is( true ) );
        coerciveParsing.nextParam();

        coerciveParsing.getTamperedRequest( "", PayloadPosition.ATTRIBUTE );
    }

    @Test( expected = IllegalArgumentException.class )
    public void getSetTest()
    {
        assertNotNull( coerciveParsing.getNumberOfTagsIterator() );

        coerciveParsing.setNumberOfTagsIterator( null );
    }

    @Test
    public void tampered()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();

        coerciveParsing.setNumberOfTagsIterator( iterateModel );
        assertThat( coerciveParsing.hasFurtherParams(), is( true ) );
        coerciveParsing.nextParam();

        String tampered = "><x><x></x></x></";
        assertThat( coerciveParsing.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( coerciveParsing.hasFurtherParams(), is( true ) );
        coerciveParsing.nextParam();

        assertThat( coerciveParsing.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untampered()
        throws ParserConfigurationException
    {
        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 4 ).stopAt( 12 ).setIncrement( 8 ).build();

        coerciveParsing.setNumberOfTagsIterator( iterateModel );
        assertThat( coerciveParsing.hasFurtherParams(), is( true ) );
        coerciveParsing.nextParam();

        String tamperedRequest = coerciveParsing.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = coerciveParsing.getUntamperedRequest( xml, payloadPosition );

        String referece = "><!-- ccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( coerciveParsing.hasFurtherParams(), is( true ) );
        coerciveParsing.nextParam();

        tamperedRequest = coerciveParsing.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = coerciveParsing.getUntamperedRequest( xml, payloadPosition );

        referece = "><!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( coerciveParsing.hasFurtherParams(), is( false ) );
    }

    @Test
    public void minimalTest()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        DoSAttack minimal = coerciveParsing.minimal();
        String tamperedRequest = minimal.getTamperedRequest( xml, payloadPosition );

        System.out.println( tamperedRequest );
        assertThat( tamperedRequest, containsString( "><x><x></x></x><" ) );
    }

    @Test
    public void compareToTest()
    {
        coerciveParsing.nextParam();

        assertThat( coerciveParsing.compareTo( coerciveParsing ), is( 0 ) );

        // different classes
        assertThat( coerciveParsing.compareTo( new HashCollision() ), is( 0 ) );

        CoerciveParsing cp = new CoerciveParsing();
        cp.setNumberOfTagsIterator( IterateModel.custom().startAt( 500 ).build() );
        cp.nextParam();
        assertThat( coerciveParsing.compareTo( cp ), is( 1 ) );

        cp = new CoerciveParsing();
        cp.setNumberOfTagsIterator( IterateModel.custom().startAt( 5000 ).build() );
        cp.nextParam();
        assertThat( coerciveParsing.compareTo( cp ), is( -1 ) );

        cp = new CoerciveParsing();
        cp.setNumberOfTagsIterator( IterateModel.custom().startAt( 2500 ).build() );
        cp.nextParam();
        assertThat( coerciveParsing.compareTo( cp ), is( 0 ) );
    }

    @Test
    public void cloneTest()
        throws CloneNotSupportedException
    {
        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 4 ).stopAt( 12 ).setIncrement( 8 ).build();

        coerciveParsing.setNumberOfTagsIterator( iterateModel );
        assertThat( coerciveParsing.hasFurtherParams(), is( true ) );
        coerciveParsing.nextParam();

        String valueAsString = coerciveParsing.getCurrentParams().get( 0 ).getValueAsString();
        assertThat( valueAsString, is( "4" ) );

        DoSAttack clone1 = coerciveParsing.clone();

        assertThat( clone1.getName(), is( "CoerciveParsing" ) );

        coerciveParsing.nextParam();
        valueAsString = coerciveParsing.getCurrentParams().get( 0 ).getValueAsString();
        assertThat( valueAsString, is( "12" ) );

        DoSAttack clone2 = coerciveParsing.clone();

        valueAsString = clone1.getCurrentParams().get( 0 ).getValueAsString();
        assertThat( valueAsString, is( "4" ) );

        valueAsString = clone2.getCurrentParams().get( 0 ).getValueAsString();
        assertThat( valueAsString, is( "12" ) );
    }

}
