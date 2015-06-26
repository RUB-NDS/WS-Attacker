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

/**
 * @author Christian Altmeier
 */
public class SimpleSuccessDecider
    extends AbstractSuccessDecider
{
    // when is an attack called succesful based on effectivness!
    private static final int payloadSuccessThreshold = 3;

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.success.SuccessDecider#wasSuccessful(java.lang.Long[], java.lang.Long[])
     */
    @Override
    public boolean wasSuccessful( Long[] run1, Long[] run2 )
    {
        double result = calculateRatio( run1, run2 );
        if ( result >= 0 )
        {
            double d = Math.round( result * 100.0 ) / 100.0;
            boolean successful = d > payloadSuccessThreshold;

            return successful;
        }
        else
        {
            return false;
        }
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.success.SuccessDecider#getEfficency(java.lang.Long[], java.lang.Long[])
     */
    @Override
    public Efficiency getEfficency( Long[] run1, Long[] run2 )
    {
        double radio = calculateRatio( run1, run2 );

        if ( radio < payloadSuccessThreshold )
        {
            return Efficiency.inefficient;
        }
        else if ( radio < 2 * payloadSuccessThreshold )
        {
            return Efficiency.efficient;
        }
        else
        {
            return Efficiency.highlyEfficient;
        }
    }

}
