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
package wsattacker.library.intelligentdos.helper;

import java.io.Serializable;

/**
 * @author Christian Altmeier
 */
public class CommonParamItem
    implements Serializable, Comparable<CommonParamItem>
{

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;

    private static final double SECOND_IN_MILLIES = 1000.0;

    private final int numberOfRequests;

    private final int numberOfThreads;

    private final int milliesBetweenRequests;

    public CommonParamItem( int numberOfRequests, int numberOfThreads, int milliesBetweenRequests )
    {
        this.numberOfRequests = numberOfRequests;
        this.numberOfThreads = numberOfThreads;
        this.milliesBetweenRequests = milliesBetweenRequests;
    }

    public CommonParamItem( int[] is )
    {
        if ( is == null || is.length != 3 )
        {
            throw new IllegalArgumentException( "only a array with exactly three elements "
                + "{requests, threads, millies} allowed" );
        }

        this.numberOfRequests = is[0];
        this.numberOfThreads = is[1];
        this.milliesBetweenRequests = is[2];
    }

    public int getNumberOfRequests()
    {
        return numberOfRequests;
    }

    public int getNumberOfThreads()
    {
        return numberOfThreads;
    }

    public int getMilliesBetweenRequests()
    {
        return milliesBetweenRequests;
    }

    public double getReuqestsPerSecond()
    {
        return SECOND_IN_MILLIES / milliesBetweenRequests * numberOfThreads;
    }

    @Override
    public String toString()
    {
        return String.format( "CommonParams[requests=%d, threads=%d, millies=%d]", numberOfRequests, numberOfThreads,
                              milliesBetweenRequests );
    }

    @Override
    public int hashCode()
    {
        return super.hashCode();
    }

    @Override
    public boolean equals( Object obj )
    {
        if ( obj == null )
        {
            return false;
        }

        if ( obj == this )
        {
            return true;
        }

        if ( !obj.getClass().equals( getClass() ) )
        {
            return false;
        }

        CommonParamItem that = (CommonParamItem) obj;

        return this.numberOfRequests == that.numberOfRequests && this.numberOfThreads == that.numberOfThreads
            && this.milliesBetweenRequests == that.milliesBetweenRequests;
    }

    @Override
    public int compareTo( CommonParamItem o )
    {
        final int BEFORE = -1;
        final int EQUAL = 0;
        final int AFTER = 1;

        // this optimization is usually worthwhile, and can
        // always be added
        if ( this == o )
            return EQUAL;

        // first compare numberOfRequests
        if ( this.numberOfRequests < o.numberOfRequests )
            return BEFORE;
        if ( this.numberOfRequests > o.numberOfRequests )
            return AFTER;

        // than compare numberOfThreads
        if ( this.numberOfThreads < o.numberOfThreads )
            return BEFORE;
        if ( this.numberOfThreads > o.numberOfThreads )
            return AFTER;

        // and at least compare milliesBetweenRequests
        if ( this.milliesBetweenRequests < o.milliesBetweenRequests )
            return BEFORE;
        if ( this.milliesBetweenRequests > o.milliesBetweenRequests )
            return AFTER;

        return EQUAL;
    }

}
