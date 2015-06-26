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

import org.apache.commons.math3.distribution.TDistribution;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.apache.commons.math3.stat.inference.TestUtils;

/**
 * @author Christian Altmeier
 */
public class TTestSuccessDecider
    extends AbstractSuccessDecider
{
    // the propability is 95%
    private static final double propability = 0.95;

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.success.SuccessDecider#wasSuccessful(java.lang.Long[], java.lang.Long[])
     */
    @Override
    public boolean wasSuccessful( Long[] run1, Long[] run2 )
    {
        double pValue = calculateProbability( run1, run2 );

        return pValue > propability;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.success.SuccessDecider#getEfficency(java.lang.Long[], java.lang.Long[])
     */
    @Override
    public Efficiency getEfficency( Long[] run1, Long[] run2 )
    {

        double pValue = calculateProbability( run1, run2 );

        if ( pValue > propability )
        {
            return Efficiency.efficient;
        }
        else
        {
            return Efficiency.inefficient;
        }
    }

    private double calculateProbability( Long[] run1, Long[] run2 )
    {
        SummaryStatistics statisticsX = new SummaryStatistics();
        for ( double value : run1 )
        {
            statisticsX.addValue( value );
        }

        SummaryStatistics statisticsY = new SummaryStatistics();
        for ( double value : run2 )
        {
            statisticsY.addValue( value );
        }

        // two-sample
        double t = TestUtils.t( statisticsX, statisticsY );
        long degreesOfFreedom = statisticsX.getN() + statisticsY.getN() - 2;
        // p-value = 0.3002
        TDistribution tDistribution = new TDistribution( degreesOfFreedom );
        double pValue = tDistribution.cumulativeProbability( t );
        return pValue;
    }

}
