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

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ianyo
 */
public class LogEntryRequestTest {
    
    LogEntryRequest instance;
    
    public LogEntryRequestTest() {
	instance = new LogEntryRequest(100, 200, 100, 10, false, false, false, "test");
    }
   

    /**
     * Test of getTsSend method, of class LogEntryRequest.
     */
    @Test
    public void testGetTsSend() {
	System.out.println("getTsSend");
	long expResult = 100;
	long result = instance.getTsSend();
	assertEquals(expResult, result);
    }

    /**
     * Test of setTsSend method, of class LogEntryRequest.
     */
    @Test
    public void testSetTsSend() {
	System.out.println("setTsSend");
	long tsSend = 100L;
	instance.setTsSend(tsSend);
    }

    /**
     * Test of getTsReceived method, of class LogEntryRequest.
     */
    @Test
    public void testGetTsReceived() {
	System.out.println("getTsReceived");
	long expResult = 200L;
	long result = instance.getTsReceived();
	assertEquals(expResult, result);
    }

    /**
     * Test of setTsReceived method, of class LogEntryRequest.
     */
    @Test
    public void testSetTsReceived() {
	System.out.println("setTsReceived");
	long tsReceived = 200L;
	instance.setTsReceived(tsReceived);
    }

    /**
     * Test of getDuration method, of class LogEntryRequest.
     */
    @Test
    public void testGetDuration() {
	System.out.println("getDuration");
	long expResult = 100L;
	long result = instance.getDuration();
	assertEquals(expResult, result);
    }

    /**
     * Test of setDuration method, of class LogEntryRequest.
     */
    @Test
    public void testSetDuration() {
	System.out.println("setDuration");
	long duration = 100L;
	instance.setDuration(duration);
    }

    /**
     * Test of getThreadNumber method, of class LogEntryRequest.
     */
    @Test
    public void testGetThreadNumber() {
	System.out.println("getThreadNumber");
	int expResult = 10;
	int result = instance.getThreadNumber();
	assertEquals(expResult, result);
    }

    /**
     * Test of setThreadNumber method, of class LogEntryRequest.
     */
    @Test
    public void testSetThreadNumber() {
	System.out.println("setThreadNumber");
	int threadNumber = 10;
	instance.setThreadNumber(threadNumber);
    }

    /**
     * Test of isTimeOutFlag method, of class LogEntryRequest.
     */
    @Test
    public void testGetTimeOutFlag() {
	System.out.println("isTimeOutFlag");
	boolean expResult = false;
	boolean result = instance.getTimeOutFlag();
	assertEquals(expResult, result);
    }

    /**
     * Test of setTimeOutFlag method, of class LogEntryRequest.
     */
    @Test
    public void testSetTimeOutFlag() {
	System.out.println("setTimeOutFlag");
	boolean timeOutFlag = false;
	instance.setTimeOutFlag(timeOutFlag);
    }

    /**
     * Test of isTimeOutFlag method, of class LogEntryRequest.
     */
    @Test
    public void testGetFaultFlag() {
	System.out.println("getFaultFlag");
	boolean expResult = false;
	boolean result = instance.getFaultFlag();
	assertEquals(expResult, result);
    }
    
    @Test
    public void testGetErrorFlag() {
	System.out.println("getErrorFlag");
	boolean expResult = false;
	boolean result = instance.getErrorFlag();
	assertEquals(expResult, result);
    }    

    /**
     * Test of setTimeOutFlag method, of class LogEntryRequest.
     */
    @Test
    public void testSetFaultFlag() {
	System.out.println("setFaultFlag");
	boolean faultFlag = false;
	instance.setFaultFlag(faultFlag);
    }    
    
    /**
     * Test of getResponseString method, of class LogEntryRequest.
     */
    @Test
    public void testGetResponseString() {
	System.out.println("getResponseString");
	String expResult = "test";
	String result = instance.getResponseString();
	assertEquals(expResult, result);
    }

    /**
     * Test of getResponseStringCsv method, of class LogEntryRequest.
     */
    @Test
    public void testGetResponseStringCsv() {
	System.out.println("getResponseStringCsv");
	String expResult = "test";
	String result = instance.getResponseStringCsv();
	assertEquals(expResult, result);
    }

    /**
     * Test of setResponseString method, of class LogEntryRequest.
     */
    @Test
    public void testSetResponseString() {
	System.out.println("setResponseString");
	String responseString = "test";
	instance.setResponseString(responseString);
    }
}
