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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.util.NoSuchElementException;

import org.junit.Test;

import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;

/**
 * @author Christian Altmeier
 */
public class MatcherPositionIteratorTest
{

    @Test
    public void threePlaceholderEach()
    {
        String xmlWithPlaceholder =
            "<soapenv:Envelope $$PAYLOADATTR$$>"
                + "   <soapenv:Header $$PAYLOADATTR$$>$$PAYLOADELEMENT$$</soapenv:Header>"
                + "   <soapenv:Body $$PAYLOADATTR$$>" + "      <cxf:celsiusToFarenheit>" + "         <arg0>1</arg0>"
                + "      </cxf:celsiusToFarenheit>" + "   $$PAYLOADELEMENT$$</soapenv:Body>"
                + "$$PAYLOADELEMENT$$</soapenv:Envelope>";

        MatcherPositionIterator iterator = new MatcherPositionIterator( xmlWithPlaceholder );

        for ( int i = 0; i < 3; i++ )
        {
            assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.TRUE ) );
            assertNotNull( iterator.next( PayloadPosition.ELEMENT ) );

            assertThat( iterator.hasNext( PayloadPosition.ATTRIBUTE ), is( Boolean.TRUE ) );
            assertNotNull( iterator.next( PayloadPosition.ATTRIBUTE ) );
        }
    }

    @Test
    public void onlyElement()
    {
        String xmlWithPlaceholder =
            "<soapenv:Envelope>" + "   <soapenv:Header>$$PAYLOADELEMENT$$</soapenv:Header>" + "   <soapenv:Body>"
                + "      <cxf:celsiusToFarenheit>" + "         <arg0>1</arg0>" + "      </cxf:celsiusToFarenheit>"
                + "   $$PAYLOADELEMENT$$</soapenv:Body>" + "$$PAYLOADELEMENT$$</soapenv:Envelope>";

        MatcherPositionIterator iterator = new MatcherPositionIterator( xmlWithPlaceholder );

        assertThat( iterator.hasNext( PayloadPosition.ATTRIBUTE ), is( Boolean.FALSE ) );

        for ( int i = 0; i < 3; i++ )
        {
            assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.TRUE ) );
            assertNotNull( iterator.next( PayloadPosition.ELEMENT ) );
        }
    }

    @Test
    public void onlyAttribute()
    {
        String xmlWithPlaceholder =
            "<soapenv:Envelope $$PAYLOADATTR$$>" + "   <soapenv:Header $$PAYLOADATTR$$ />"
                + "   <soapenv:Body $$PAYLOADATTR$$>" + "      <cxf:celsiusToFarenheit>" + "         <arg0>1</arg0>"
                + "      </cxf:celsiusToFarenheit>" + "   </soapenv:Body>" + "</soapenv:Envelope>";

        MatcherPositionIterator iterator = new MatcherPositionIterator( xmlWithPlaceholder );

        assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.FALSE ) );

        for ( int i = 0; i < 3; i++ )
        {
            assertThat( iterator.hasNext( PayloadPosition.ATTRIBUTE ), is( Boolean.TRUE ) );
            assertNotNull( iterator.next( PayloadPosition.ATTRIBUTE ) );
        }
    }

    @Test
    public void none()
    {
        String xmlWithPlaceholder =
            "<soapenv:Envelope>" + "   <soapenv:Header />" + "   <soapenv:Body >" + "      <cxf:celsiusToFarenheit>"
                + "         <arg0>1</arg0>" + "      </cxf:celsiusToFarenheit>" + "   </soapenv:Body>"
                + "</soapenv:Envelope>";

        MatcherPositionIterator iterator = new MatcherPositionIterator( xmlWithPlaceholder );

        assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.FALSE ) );
        assertThat( iterator.hasNext( PayloadPosition.ATTRIBUTE ), is( Boolean.FALSE ) );
    }

    @Test( expected = NoSuchElementException.class )
    public void noneWithExcpetion()
    {
        String xmlWithPlaceholder =
            "<soapenv:Envelope>" + "   <soapenv:Header />" + "   <soapenv:Body >" + "      <cxf:celsiusToFarenheit>"
                + "         <arg0>1</arg0>" + "      </cxf:celsiusToFarenheit>" + "   </soapenv:Body>"
                + "</soapenv:Envelope>";

        MatcherPositionIterator iterator = new MatcherPositionIterator( xmlWithPlaceholder );

        assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.FALSE ) );
        iterator.next( PayloadPosition.ELEMENT );
    }

    @Test
    public void resetTest()
    {
        String xmlWithPlaceholder =
            "<soapenv:Envelope>" + "   <soapenv:Header>$$PAYLOADELEMENT$$</soapenv:Header>" + "   <soapenv:Body>"
                + "      <cxf:celsiusToFarenheit>" + "         <arg0>1</arg0>" + "      </cxf:celsiusToFarenheit>"
                + "   $$PAYLOADELEMENT$$</soapenv:Body>" + "$$PAYLOADELEMENT$$</soapenv:Envelope>";

        MatcherPositionIterator iterator = new MatcherPositionIterator( xmlWithPlaceholder );

        assertThat( iterator.hasNext( PayloadPosition.ATTRIBUTE ), is( Boolean.FALSE ) );

        for ( int i = 0; i < 3; i++ )
        {
            assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.TRUE ) );
            assertNotNull( iterator.next( PayloadPosition.ELEMENT ) );
        }

        assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.FALSE ) );

        iterator.reset();
        for ( int i = 0; i < 3; i++ )
        {
            assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.TRUE ) );
            assertNotNull( iterator.next( PayloadPosition.ELEMENT ) );
        }
    }

    @Test
    public void positionToStringOneTest()
    {
        String onePlaceholder =
            "<soapenv:Envelope>" + "   <soapenv:Header></soapenv:Header>" + "   <soapenv:Body>"
                + "      <cxf:celsiusToFarenheit>" + "         <arg0>1</arg0>" + "      </cxf:celsiusToFarenheit>"
                + "   $$PAYLOADELEMENT$$</soapenv:Body>" + "</soapenv:Envelope>";

        MatcherPositionIterator iterator = new MatcherPositionIterator( onePlaceholder );

        assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.TRUE ) );
        Position position = iterator.next( PayloadPosition.ELEMENT );
        assertNotNull( position );

        assertThat( position.toString(), is( "position 1 / 1" ) );
    }

    @Test
    public void positionToStringTwoTest()
    {
        String twoPlaceholders =
            "<soapenv:Envelope>" + "   <soapenv:Header>$$PAYLOADELEMENT$$</soapenv:Header>" + "   <soapenv:Body>"
                + "      <cxf:celsiusToFarenheit>" + "         <arg0>1</arg0>" + "      </cxf:celsiusToFarenheit>"
                + "   $$PAYLOADELEMENT$$</soapenv:Body>" + "</soapenv:Envelope>";

        MatcherPositionIterator iterator = new MatcherPositionIterator( twoPlaceholders );

        assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.TRUE ) );
        Position position = iterator.next( PayloadPosition.ELEMENT );
        assertNotNull( position );

        assertThat( position.toString(), is( "position 1 / 2" ) );

        assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.TRUE ) );
        position = iterator.next( PayloadPosition.ELEMENT );
        assertNotNull( position );

        assertThat( position.toString(), is( "position 2 / 2" ) );
    }

}