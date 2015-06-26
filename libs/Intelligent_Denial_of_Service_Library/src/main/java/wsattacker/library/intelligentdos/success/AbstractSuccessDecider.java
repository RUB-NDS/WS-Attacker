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

import org.apache.commons.math3.stat.descriptive.rank.Median;

/**
 * @author Christian Altmeier
 */
public abstract class AbstractSuccessDecider
    implements SuccessDecider
{

    private static final int sampleCountAttackEffectivness = 10;

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.success.SuccessDecider#calculateRatio(java.lang.Long[], java.lang.Long[])
     */
    @Override
    public double calculateRatio( Long[] run1, Long[] run2 )
    {
        double medianFirstRun = calculateMedian( run1 );

        double medianSecondRun = calculateMedian( run2 );

        double timeDelta = ( (float) medianSecondRun / (float) ( medianFirstRun ) );
        return timeDelta; // ns = 10^9 to delta_ms
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.success.SuccessDecider#calculateMedian(java.lang.Long[])
     */
    @Override
    public double calculateMedian( Long[] run )
    {
        Median median = new Median();
        int sampleCountMax1 =
            ( run.length < sampleCountAttackEffectivness ) ? run.length : sampleCountAttackEffectivness;

        // Loop last 10 untampered AttackRequests and calculate median
        double medianUntampered = 0;
        double[] medianUntamperedArray = new double[sampleCountMax1];
        for ( int i = 1; i <= sampleCountMax1; i++ )
        {
            medianUntamperedArray[i - 1] = run[run.length - i];
        }
        medianUntampered = median.evaluate( medianUntamperedArray );
        return medianUntampered;
    }
}
