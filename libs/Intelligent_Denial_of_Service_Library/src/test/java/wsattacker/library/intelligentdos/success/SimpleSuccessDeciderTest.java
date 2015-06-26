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
package wsattacker.library.intelligentdos.success;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * @author Christian Altmeier
 */
public class SimpleSuccessDeciderTest
{

    private final SimpleSuccessDecider simpleSuccessDecider = new SimpleSuccessDecider();

    @Test
    public void wasSuccessfulTest()
    {
        Long[] run1 = { 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l };
        Long[] run2 = { 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l };

        assertThat( simpleSuccessDecider.wasSuccessful( run1, run2 ), is( Boolean.FALSE ) );

        run2 = new Long[] { 8l, 8l, 8l, 8l, 8l, 8l, 8l, 8l, 8l, 8l };
        assertThat( simpleSuccessDecider.wasSuccessful( run1, run2 ), is( Boolean.TRUE ) );
    }

    @Test
    public void getEfficencyTest()
    {
        Long[] run1 = { 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l };
        Long[] run2 = { 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l };

        assertThat( simpleSuccessDecider.getEfficency( run1, run2 ), is( Efficiency.inefficient ) );

        run2 = new Long[] { 3l, 3l, 3l, 3l, 3l, 3l, 3l, 3l, 3l, 3l };
        assertThat( simpleSuccessDecider.getEfficency( run1, run2 ), is( Efficiency.efficient ) );

        run2 = new Long[] { 8l, 8l, 8l, 8l, 8l, 8l, 8l, 8l, 8l, 8l };
        assertThat( simpleSuccessDecider.getEfficency( run1, run2 ), is( Efficiency.highlyEfficient ) );
    }

}
