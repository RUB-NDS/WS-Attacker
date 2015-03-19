/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.mvc.model;

import java.util.List;

import org.apache.commons.math3.stat.descriptive.rank.Median;

import wsattacker.plugin.dos.dosExtension.logEntry.LogEntryRequest;

public class AttackRoundtrip
{

    // Median Values
    private double medianUntampered;

    private double medianTampered;

    private long tsTamperedLastSend;

    // How many samples should we take to calculate attackEffectivness?
    private final int sampleCountAttackEffectivness = 10;

    public double getMedianUntampered()
    {
        return medianUntampered;
    }

    public void setMedianUntampered( double medianUntampered )
    {
        this.medianUntampered = medianUntampered;
    }

    public double getMedianTampered()
    {
        return medianTampered;
    }

    public void setMedianTampered( double medianTampered )
    {
        this.medianTampered = medianTampered;
    }

    /**
     * metric used to test for vulnerability Sets responseTimeMeanUntampered and responseTimeMeanTampered in relation
     * <ul>
     * <li>Result = 1: <br />
     * No difference between tampered and untampered requests</li>
     * <li>Result &lt; 1: <br />
     * response time of tampered Requests is even lower than the response time of untampered requests -> attack not
     * successful!</li>
     * <li>Result &gt; 1: <br />
     * response time of tampered Requests are higher than response time of untampered requests. In this case the attack
     * is successful! The attack can be considered as a success when the result is higher than 2 points</li>
     * </ul>
     * Defined as: (responseTimeMeanTampered / responseTimeMeanUntampered)
     * 
     * @return Points
     */
    public double getTimeRatio( List<LogEntryRequest> untampered, List<LogEntryRequest> tampered )
    {
        try
        {
            Median median = new Median();
            int sampleCountMax =
                ( untampered.size() < sampleCountAttackEffectivness ) ? untampered.size()
                                : sampleCountAttackEffectivness;

            // Loop last 10 untampered AttackRequests and calculate median
            medianUntampered = 0;
            double[] medianUntamperedArray = new double[sampleCountMax];
            for ( int i = 1; i <= sampleCountMax; i++ )
            {
                medianUntamperedArray[i - 1] = untampered.get( untampered.size() - i ).getDuration();
            }
            medianUntampered = median.evaluate( medianUntamperedArray );

            // Loop last 10 tampered AttackRequests and calculate median
            medianTampered = 0;
            double[] medianTamperedArray = new double[sampleCountMax];
            for ( int i = 1; i <= sampleCountMax; i++ )
            {
                medianTamperedArray[i - 1] = tampered.get( tampered.size() - i ).getDuration();
            }
            medianTampered = median.evaluate( medianTamperedArray );

            double timeDelta = ( (float) medianTampered / (float) ( medianUntampered ) );
            double result = timeDelta; // ns = 10^9 to delta_ms
            if ( result >= 0 )
            {
                return Math.round( result * 100.0 ) / 100.0;
            }
            else
            {
                return 0.0;
            }
        }
        catch ( Exception e )
        {
            return 0.0;
        }
    }

    /**
     * Calculate attack effect on third party users. Output ms of mean of all testprobe requests after attack started
     * Makes a statement in regard of longterm effect on thrid party users!
     * 
     * @param testProbe TODO
     * @return
     */
    public double getTestProbeAttackRoundtripTime( List<LogEntryRequest> testProbe )
    {
        // Only if we have data
        if ( testProbe.size() > 0 )
        {
            Median median = new Median();
            int sampleCountMaxTestProbes = 0;

            // Count number of suitable logRequestObjectss
            for ( int i = 0; i < testProbe.size(); i++ )
            {
                if ( testProbe.get( i ).getTsSend() > tsTamperedLastSend )
                {
                    sampleCountMaxTestProbes++;
                    // System.out.println(sampleCountMaxTestProbes+" - "+logListTestProbeRequests.get(i).getTsSend()
                    // +" - "+ tsTamperedLastSend);
                }
            }
            double[] medianTestProbesArray = new double[sampleCountMaxTestProbes];

            // Save duration in array for median
            for ( int i = 0, k = 0; i < testProbe.size(); i++, k++ )
            {
                if ( testProbe.get( i ).getTsSend() > tsTamperedLastSend )
                {
                    medianTestProbesArray[k] = testProbe.get( i ).getDuration();
                }
            }
            double medianTestProbes = median.evaluate( medianTestProbesArray );
            double result = medianTestProbes / 1000000000;
            return Math.round( result * 1000.0 ) / 1000.0;
        }
        return 0;
    }
}
