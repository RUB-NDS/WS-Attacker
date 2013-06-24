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

import org.apache.commons.lang3.StringUtils;




/**
 * Log Entry of single Request send out by attack threads!
 * includes all relevant data of Request needed for processing in later stage
 * @author Andreas Falkenberg
 *
 */
public class LogEntryRequest
{
	private long  tsSend;		// ms = 10^3
	private long  tsReceived;	// ms = 10^3
	private long duration;		// ns = 10^9
	private int threadNumber;
	private boolean timeOutFlag;
	private boolean faultFlag;
	private boolean errorFlag;
	private String responseString;
	
	/**
	 * Konstruktor
	 * @param tsSend
	 * @param tsReceived
	 * @param threadNumber
	 * @param timeOutFlag
	 * @param responseString
	 */
	public LogEntryRequest(long  tsSend, long  tsReceived, long duration, int threadNumber, boolean timeOutFlag, boolean faultFlag,  boolean errorFlag, String responseString){
		this.tsSend = tsSend;
		this.tsReceived = tsReceived; 
		this.threadNumber = threadNumber; 
		this.duration = duration; 
		this.timeOutFlag = timeOutFlag; 
		this.faultFlag = faultFlag; 
		this.errorFlag = errorFlag; 
		this.responseString = responseString;
	}


	public long getTsSend()
	{
		return tsSend;
	}

	public void setTsSend( long tsSend )
	{
		this.tsSend = tsSend;
	}

	public long getTsReceived()
	{
		return tsReceived;
	}

	public void setTsReceived( long tsReceived )
	{
		this.tsReceived = tsReceived;
	}
	
	public long getDuration()
	{
		return duration;
	}

	public void setDuration( long duration )
	{
		this.duration = duration;
	}


	public int getThreadNumber()
	{
		return threadNumber;
	}

	public void setThreadNumber( int threadNumber )
	{
		this.threadNumber = threadNumber;
	}

	public boolean getTimeOutFlag()
	{
		return timeOutFlag;
	}
	
	public boolean getFaultFlag()
	{
		return faultFlag;
	}	

	public boolean getErrorFlag()
	{
		return errorFlag;
	}	
	
	public void setTimeOutFlag( boolean timeOutFlag )
	{
		this.timeOutFlag = timeOutFlag;
	}
	
	public void setFaultFlag( boolean faultFlag )
	{
		this.faultFlag = faultFlag;
	}	
	
	public void setErrorFlag( boolean errorFlag )
	{
		this.errorFlag = errorFlag;
	}		

	public String getResponseString()
	{
		return responseString;
	}
	
	public String getResponseStringCsv()
	{
		return escapeForCSV(responseString);
	}	
	


	public void setResponseString( String responseString )
	{
		this.responseString = responseString;
	}
	
	/**
	 * Escapes complete SOAP-Response for CSV-Usage!
	 * see http://commons.apache.org/lang/api-2.4/org/apache/commons/lang/StringEscapeUtils.html#escapeCsv%28java.lang.String%29
	 * 
	 * @param sArg
	 * @return 
	 */
	private static String escapeForCSV(String sArg)
	{
        StringBuffer sb = new StringBuffer();
        if (sArg != null)
        {
            if ((sArg.indexOf(",") >= 0) || (sArg.indexOf("\n") >= 0) || (sArg.indexOf("\r") >= 0)
                || (sArg.indexOf("\"") >= 0))
            {
                sb.append("\"");
                sb.append(StringUtils.replace(sArg, "\"", "\"\"")); // escape " with ""
                sb.append("\"");
            }
            else
            {
                sb.append(sArg);
            }
        }

        return sb.toString();
	}	
	
	
	
}
