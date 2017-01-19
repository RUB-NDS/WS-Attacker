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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;

/**
 * @author Christian Altmeier
 */
public class SchemaAnalyzerPositionIteratorTest
{

    private static String xmlMessage =
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axis=\"http://axis2.wsattacker\">"
            + "   <soapenv:Header/>" + "   <soapenv:Body>" + "      <axis:reverser>" + "         <!--Optional:-->"
            + "         <axis:toReverse>?</axis:toReverse>" + "      </axis:reverser>" + "   </soapenv:Body>"
            + "</soapenv:Envelope>";

    // The SchemaAnalyzer
    private final SchemaAnalyzer schemaAnalyzer = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );

    @Test( expected = IllegalArgumentException.class )
    public void constructor()
    {
        SchemaAnalyzerPositionIterator positionIterator = new SchemaAnalyzerPositionIterator( null, xmlMessage );
        assertNull( positionIterator );
    }

    @Test( expected = IllegalArgumentException.class )
    public void defectXml()
    {
        SchemaAnalyzerPositionIterator positionIterator =
            new SchemaAnalyzerPositionIterator( schemaAnalyzer, "abcdefg" );
        assertNull( positionIterator );
    }

    @Test
    public void expansionPointTest()
    {
        SchemaAnalyzerPositionIterator positionIterator =
            new SchemaAnalyzerPositionIterator( schemaAnalyzer, xmlMessage );

        int count = 0;
        while ( positionIterator.hasNext( PayloadPosition.ELEMENT ) )
        {
            positionIterator.next( PayloadPosition.ELEMENT );
            count++;
        }
        assertThat( count, is( 3 ) );
    }

    @Test
    public void noExpansionPointTest()
    {
        String xmlMessage2 = "<?xml version=\"1.0\"?><Envelope><Header></Header><Body></Body></Envelope>";
        SchemaAnalyzerPositionIterator positionIterator =
            new SchemaAnalyzerPositionIterator( schemaAnalyzer, xmlMessage2 );
        assertFalse( positionIterator.hasNext( PayloadPosition.ELEMENT ) );
        assertFalse( positionIterator.hasNext( PayloadPosition.ATTRIBUTE ) );
    }

    @Test
    public void iterateOverAll()
    {
        SchemaAnalyzerPositionIterator iterator = new SchemaAnalyzerPositionIterator( schemaAnalyzer, xmlMessage );
        for ( int i = 0; i < 3; i++ )
        {
            assertThat( iterator.hasNext( PayloadPosition.ELEMENT ), is( Boolean.TRUE ) );
            assertNotNull( iterator.next( PayloadPosition.ELEMENT ) );

            assertThat( iterator.hasNext( PayloadPosition.ATTRIBUTE ), is( Boolean.TRUE ) );
            assertNotNull( iterator.next( PayloadPosition.ATTRIBUTE ) );
        }

        assertThat( iterator.hasNext( null ), is( Boolean.FALSE ) );
    }

}
