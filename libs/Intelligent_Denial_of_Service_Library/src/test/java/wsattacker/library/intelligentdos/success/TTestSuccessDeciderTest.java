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
public class TTestSuccessDeciderTest
{

    private final TTestSuccessDecider tTestSuccessDecider = new TTestSuccessDecider();

    @Test
    public void wasSuccessfulTest()
    {
        Long[] run1 = { 15l, 10l, 13l, 7l, 9l, 8l, 21l, 9l, 14l, 8l };
        Long[] run2 = { 15l, 14l, 12l, 8l, 14l, 7l, 16l, 10l, 15l, 12l };
        assertThat( tTestSuccessDecider.wasSuccessful( run1, run2 ), is( false ) );

        run2 = new Long[] { 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l };
        assertThat( tTestSuccessDecider.wasSuccessful( run1, run2 ), is( true ) );
    }

    @Test
    public void Test()
    {
        Long[] run1 = { 15l, 10l, 13l, 7l, 9l, 8l, 21l, 9l, 14l, 8l };
        Long[] run2 = { 15l, 14l, 12l, 8l, 14l, 7l, 16l, 10l, 15l, 12l };
        assertThat( tTestSuccessDecider.getEfficency( run1, run2 ), is( Efficiency.inefficient ) );

        run2 = new Long[] { 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l, 1l };
        assertThat( tTestSuccessDecider.getEfficency( run1, run2 ), is( Efficiency.efficient ) );
    }

}
