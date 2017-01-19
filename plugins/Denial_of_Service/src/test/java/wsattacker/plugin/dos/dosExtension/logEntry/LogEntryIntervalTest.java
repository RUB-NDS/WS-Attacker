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

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author ianyo
 */
public class LogEntryIntervalTest
{

    public LogEntryIntervalTest()
    {
    }

    /**
     * Test of getIntervalNumber method, of class LogEntryInterval.
     */
    @Test
    public void testGetIntervalNumber()
    {
        LogEntryInterval instance = new LogEntryInterval();
        int expResult = -1;
        int result = instance.getIntervalNumber();
        assertEquals( expResult, result );
    }

    /**
     * Test of setIntervalNumber method, of class LogEntryInterval.
     */
    @Test
    public void testSetIntervalNumber()
    {
        int intervalNumber = 0;
        LogEntryInterval instance = new LogEntryInterval();
        instance.setIntervalNumber( intervalNumber );
    }

    /**
     * Test of getNumberRequests method, of class LogEntryInterval.
     */
    @Test
    public void testGetNumberRequests()
    {
        LogEntryInterval instance = new LogEntryInterval();
        int expResult = 0;
        int result = instance.getNumberRequests();
        assertEquals( expResult, result );
    }

    /**
     * Test of incNumberRequests method, of class LogEntryInterval.
     */
    @Test
    public void testIncNumberRequests()
    {
        LogEntryInterval instance = new LogEntryInterval();
        int expResult = instance.getNumberRequests() + 1;
        instance.incNumberRequests();
        int result = instance.getNumberRequests();
        assertEquals( expResult, result );
    }

    /**
     * Test of setNumberRequests method, of class LogEntryInterval.
     */
    @Test
    public void testSetNumberRequests()
    {
        int numberRequests = 0;
        LogEntryInterval instance = new LogEntryInterval();
        instance.setNumberRequests( numberRequests );
    }

    /**
     * Test of getMeanResponseTime method, of class LogEntryInterval.
     */
    @Test
    public void testGetMeanResponseTime()
    {
        LogEntryInterval instance = new LogEntryInterval();
        float expResult = 0.0F;
        float result = instance.getMeanResponseTime();
        assertEquals( expResult, result, 0.0 );
    }

    /**
     * Test of setMeanResponseTime method, of class LogEntryInterval.
     */
    @Test
    public void testSetMeanResponseTime()
    {
        float meanResponseTime = 0.0F;
        LogEntryInterval instance = new LogEntryInterval();
        instance.setMeanResponseTime( meanResponseTime );
    }
}
