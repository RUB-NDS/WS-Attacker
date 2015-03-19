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
package wsattacker.plugin.dos.dosExtension.logEntry;

/**
 * Data Structure of single discrete Interval that is printed out in Graph!
 * 
 * @author Andreas Falkenberg
 */
public class LogEntryInterval
{
    private int intervalNumber;

    private int intervalLength; // in ms

    private int numberRequests;

    private float meanResponseTime;

    /**
     * Konstruktor
     */
    public LogEntryInterval()
    {
        this.intervalNumber = -1;
        this.intervalLength = 1000;
        this.meanResponseTime = 0;
        this.numberRequests = 0;
    }

    public int getIntervalNumber()
    {
        return intervalNumber;
    }

    public void setIntervalNumber( int intervalNumber )
    {
        this.intervalNumber = intervalNumber;
    }

    public int getIntervalLength()
    {
        return intervalLength;
    }

    public void setIntervalLength( int intervalLength )
    {
        this.intervalLength = intervalLength;
    }

    public int getNumberRequests()
    {
        return numberRequests;
    }

    public void incNumberRequests()
    {
        numberRequests++;
    }

    public void setNumberRequests( int numberRequests )
    {
        this.numberRequests = numberRequests;
    }

    public float getMeanResponseTime()
    {
        return meanResponseTime;
    }

    public void setMeanResponseTime( float meanResponseTime )
    {
        this.meanResponseTime = meanResponseTime;
    }

}
