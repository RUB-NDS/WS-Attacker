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

import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * @author ianyo
 */
public class LogEntryRequestTest
{

    LogEntryRequest instance;

    public LogEntryRequestTest()
    {
        instance = new LogEntryRequest( "type", 100, 200, 100, 10, false, false, "test" );
    }

    /**
     * Test of getTsSend method, of class LogEntryRequest.
     */
    @Test
    public void testGetTsSend()
    {
        long expResult = 100;
        long result = instance.getTsSend();
        assertEquals( expResult, result );
    }

    /**
     * Test of setTsSend method, of class LogEntryRequest.
     */
    @Test
    public void testSetTsSend()
    {
        long tsSend = 100L;
        instance.setTsSend( tsSend );
    }

    /**
     * Test of getTsReceived method, of class LogEntryRequest.
     */
    @Test
    public void testGetTsReceived()
    {
        long expResult = 200L;
        long result = instance.getTsReceived();
        assertEquals( expResult, result );
    }

    /**
     * Test of setTsReceived method, of class LogEntryRequest.
     */
    @Test
    public void testSetTsReceived()
    {
        long tsReceived = 200L;
        instance.setTsReceived( tsReceived );
    }

    /**
     * Test of getDuration method, of class LogEntryRequest.
     */
    @Test
    public void testGetDuration()
    {
        long expResult = 100L;
        long result = instance.getDuration();
        assertEquals( expResult, result );
    }

    /**
     * Test of setDuration method, of class LogEntryRequest.
     */
    @Test
    public void testSetDuration()
    {
        long duration = 100L;
        instance.setDuration( duration );
    }

    /**
     * Test of getThreadNumber method, of class LogEntryRequest.
     */
    @Test
    public void testGetThreadNumber()
    {
        int expResult = 10;
        int result = instance.getThreadNumber();
        assertEquals( expResult, result );
    }

    /**
     * Test of setThreadNumber method, of class LogEntryRequest.
     */
    @Test
    public void testSetThreadNumber()
    {
        int threadNumber = 10;
        instance.setThreadNumber( threadNumber );
    }

    /**
     * Test of isTimeOutFlag method, of class LogEntryRequest.
     */
    @Test
    public void testGetFaultFlag()
    {
        boolean expResult = false;
        boolean result = instance.getFaultFlag();
        assertEquals( expResult, result );
    }

    @Test
    public void testGetErrorFlag()
    {
        boolean expResult = false;
        boolean result = instance.getErrorFlag();
        assertEquals( expResult, result );
    }

    /**
     * Test of setTimeOutFlag method, of class LogEntryRequest.
     */
    @Test
    public void testSetFaultFlag()
    {
        boolean faultFlag = false;
        instance.setFaultFlag( faultFlag );
    }

    /**
     * Test of getResponseString method, of class LogEntryRequest.
     */
    @Test
    public void testGetResponseString()
    {
        String expResult = "test";
        String result = instance.getResponseString();
        assertEquals( expResult, result );
    }

    /**
     * Test of getResponseStringCsv method, of class LogEntryRequest.
     */
    @Test
    public void testGetResponseStringCsv()
    {
        String expResult = "test";
        String result = instance.getResponseStringCsv();
        assertEquals( expResult, result );
    }

    /**
     * Test of setResponseString method, of class LogEntryRequest.
     */
    @Test
    public void testSetResponseString()
    {
        String responseString = "test";
        instance.setResponseString( responseString );
    }
}
