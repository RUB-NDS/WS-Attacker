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
package wsattacker.library.intelligentdos.common;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;

/**
 * @author Christian Altmeier
 */
public class MetricTest
{

    private final Metric metric = new Metric();

    @Test
    public void test()
    {
        long duration = 1000l;
        String content = "Lorem ipsum";

        metric.setDuration( duration );
        assertThat( metric.getDuration(), is( duration ) );

        metric.setContent( content );
        assertThat( metric.getContent(), is( content ) );
    }

    @Test
    public void testEmpty()
    {
        assertThat( metric.isEmptyResponse(), is( true ) );

        metric.setContent( "Lorem ipsum" );
        assertThat( metric.isEmptyResponse(), is( false ) );
    }

    @Test
    public void testFault()
    {
        assertThat( metric.isSOAPFault(), is( false ) );

        metric.setContent( "Lorem ipsum" );
        assertThat( metric.isSOAPFault(), is( false ) );

        metric.setContent( "<soap:body><Fault>Fehler</Fault></soap:body>" );
        assertThat( metric.isSOAPFault(), is( true ) );
    }

}
