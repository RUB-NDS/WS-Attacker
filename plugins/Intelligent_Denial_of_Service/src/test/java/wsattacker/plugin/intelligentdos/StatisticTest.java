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
package wsattacker.plugin.intelligentdos;

import java.text.DecimalFormat;

import org.apache.commons.math3.distribution.TDistribution;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.apache.commons.math3.stat.inference.TestUtils;

public class StatisticTest
{

    // http://www.math.csi.cuny.edu/Statistics/R/simpleR/stat012.html

    public static void main( String[] args )
    {

        double[] withDrug = { 15, 10, 13, 7, 9, 8, 21, 9, 14, 8 };
        double[] placebo = { 15, 14, 12, 8, 14, 7, 16, 10, 15, 12 };
        // statistics(withDrug, placebo);

        double[] experimental =
            { 2, 2, 2, 3, 3, 1, 3, 3, 4, 3, 1, 2, 3, 2, 0, 2, 3, 2, 2, 2, 4, 3, 1, 2, 2, 1, 2, 2, 3, 0 };
        double[] kontroll =
            { 3, 2, 3, 4, 0, 2, 4, 2, 3, 2, 2, 5, 3, 5, 3, 4, 3, 3, 3, 2, 3, 2, 4, 3, 3, 4, 4, 2, 3, 3 };
        // statistics(experimental, kontroll);

        double[] x = { 3, 0, 5, 2, 5, 5, 5, 4, 4, 5 };
        double[] y = { 2, 1, 4, 1, 4, 3, 3, 2, 3, 5 };
        // statistics(x, y);

        double[] utr1 =
            { 1025090, 1016940, 30776545, 851827, 1009695, 843979, 934836, 1111118, 1024788, 949929, 1019657, 1057086,
                1018751, 905859, 1265364, 1330564, 997320, 769120, 1032334, 969851, 1613702, 897709, 1407235, 1160320,
                1041390, 1144624, 26599816, 26644490, 1520731, 1185977, 1184468, 24128251 };
        double[] utr2 =
            { 1599839, 2662677, 1427782, 1425669, 2240077, 109574, 753736, 1086382, 1575088, 1898979, 1057101, 1068874,
                1898678, 1774615, 1712734, 2054737, 1900791, 1118982, 1085476, 1092720, 1680134, 142778, 1780651,
                1786085, 2228909, 1129547, 1049857, 1040198, 972883, 1468834, 735625, 1074308 };
        double[] utr3 =
            { 108668, 119234, 70936, 103839, 123157, 99009, 184737, 73352, 104443, 118932, 83917, 74861, 112593, 77879,
                74257, 74559, 114102, 80595, 92670, 120139, 109272, 97801, 83313, 71238, 118026, 126780, 95085, 99009,
                109574, 103537, 208583, 118931 };
        System.out.println( "utr1 <> utr2" );
        statistics( utr1, utr2 );
        System.out.println();
        System.out.println( "utr1 <> utr3" );
        statistics( utr1, utr3 );
        System.out.println();
        statistics( utr2, utr3 );
    }

    private static void statistics( double[] x, double[] y )
    {

        DecimalFormat df = new DecimalFormat( "#.######" );

        SummaryStatistics statisticsX = new SummaryStatistics();
        for ( double value : x )
        {
            statisticsX.addValue( value );
        }

        SummaryStatistics statisticsY = new SummaryStatistics();
        for ( double value : y )
        {
            statisticsY.addValue( value );
        }

        // t = -0.5331
        double t = TestUtils.t( statisticsX, statisticsY );
        // df = 18
        long degreesOfFreedom = statisticsX.getN() + statisticsY.getN() - 2;
        // p-value = 0.3002
        TDistribution tDistribution = new TDistribution( degreesOfFreedom );
        double pValue = tDistribution.cumulativeProbability( t );
        // t = -0.5331, df = 18, p-value = 0.3002

        // t = -0.5331, df = 18, p-value = 0.3002
        System.out.print( "t = " + df.format( t ) );
        System.out.print( ", df = " + degreesOfFreedom );
        System.out.println( ", p-value = " + df.format( pValue ) );

        System.out.println( "mean of x mean of y" );
        System.out.println( df.format( statisticsX.getMean() ) + " - " + df.format( statisticsY.getMean() ) );

        // Calculate 95% confidence interval
        double ci = calcMeanCI( statisticsY, 0.95 );
    }

    private static double calcMeanCI( SummaryStatistics stats, double level )
    {
        // Create T Distribution with N-1 degrees of freedom
        TDistribution tDist = new TDistribution( stats.getN() - 1 );
        // Calculate critical value
        double critVal = tDist.inverseCumulativeProbability( 1.0 - ( 1 - level ) / 2 );
        // Calculate confidence interval
        return critVal * stats.getStandardDeviation() / Math.sqrt( stats.getN() );
    }

    private static void standardDeviation( SummaryStatistics statisticsWithDrug, SummaryStatistics statisticsPlacebo )
    {
        System.out.println( "standardDeviation: " + statisticsWithDrug.getStandardDeviation() );
    }
}
