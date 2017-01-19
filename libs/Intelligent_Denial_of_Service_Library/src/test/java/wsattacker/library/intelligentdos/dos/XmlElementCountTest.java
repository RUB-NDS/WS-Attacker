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
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.testhelper.IDoSTestHelper;

/**
 * @author Christian Altmeier
 */
public class XmlElementCountTest
{
    private final XmlElementCount xmlElementCount = new XmlElementCount();

    @Test
    public void hasFurther()
    {
        assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
    }

    @Test
    public void oneIteration()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlElementCount.setNumberOfElementsIterator( iterateModel );
        assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
        xmlElementCount.nextParam();
        assertThat( xmlElementCount.hasFurtherParams(), is( false ) );
    }

    @Test
    public void twoTwo()
    {
        // two number of attributes
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();
        xmlElementCount.setNumberOfElementsIterator( iterateModel );
        // use namespace: true and false
        xmlElementCount.setElements( new String[] { "a", "b" } );

        for ( int i = 0; i < 4; i++ )
        {
            assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
            xmlElementCount.nextParam();
        }

        assertThat( xmlElementCount.hasFurtherParams(), is( false ) );
    }

    @Test( expected = IllegalArgumentException.class )
    public void notAllowedPayloadPosition()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlElementCount.setNumberOfElementsIterator( iterateModel );
        assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
        xmlElementCount.nextParam();

        xmlElementCount.getTamperedRequest( "", PayloadPosition.ATTRIBUTE );
    }

    @Test( expected = IllegalArgumentException.class )
    public void nullPayloadPosition()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 2 ).build();
        xmlElementCount.setNumberOfElementsIterator( iterateModel );
        assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
        xmlElementCount.nextParam();

        xmlElementCount.getTamperedRequest( "", null );
    }

    @Test
    public void tampered()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;
        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).build();

        xmlElementCount.setNumberOfElementsIterator( iterateModel );
        assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
        xmlElementCount.nextParam();

        String tampered = "><!--X--><!--X--></";
        assertThat( xmlElementCount.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
        xmlElementCount.nextParam();

        tampered = "><!--X--><!--X--><!--X--><!--X--></";
        assertThat( xmlElementCount.getTamperedRequest( xml, payloadPosition ), containsString( tampered ) );

        assertThat( xmlElementCount.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untampered()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;
        String xml = IDoSTestHelper.createTestString( payloadPosition );

        // Iterate
        IterateModel iterateModel = IterateModel.custom().startAt( 4 ).stopAt( 12 ).setIncrement( 8 ).build();

        xmlElementCount.setNumberOfElementsIterator( iterateModel );
        xmlElementCount.setElements( new String[] { "<a />" } );
        assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
        xmlElementCount.nextParam();

        String tamperedRequest = xmlElementCount.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = xmlElementCount.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertThat( untamperedRequest, containsString( "><!-- ccccccccccc --></" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlElementCount.hasFurtherParams(), is( true ) );
        xmlElementCount.nextParam();

        tamperedRequest = xmlElementCount.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlElementCount.getUntamperedRequest( xml, payloadPosition );

        // Test structure
        assertThat( untamperedRequest,
                    containsString( "><!-- ccccccccccccccccccccccccccccccccccccccccccccccccccc --></" ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlElementCount.hasFurtherParams(), is( false ) );
    }
}
