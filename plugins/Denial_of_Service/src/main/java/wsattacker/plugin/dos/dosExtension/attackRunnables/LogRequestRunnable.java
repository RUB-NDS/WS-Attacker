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
package wsattacker.plugin.dos.dosExtension.attackRunnables;

import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * Logs Request-Responsetime 
 * This runable should be called in context of EDT
 */
public class LogRequestRunnable implements Runnable {
	private AttackModel model;
	private String requestType; 
	private long tsSend;
	private long tsReceived;
	private long duration;  
	private int threadNumber; 
	private boolean timeOutFlag;
	private boolean faultFlag;
	private boolean errorFlag;
	private String responseString;
	
	
	// Constructor
	public LogRequestRunnable(AttackModel model, String requestType, long tsSend, long tsReceived, long duration, int threadNumber, boolean timeOutFlag, boolean faultFlag, boolean errorFlag, String responseString){
		this.model = model;	
		this.requestType = requestType; 
		this.tsSend = tsSend;
		this.tsReceived = tsReceived;
		this.duration = duration;  
		this.threadNumber = threadNumber; 
		this.timeOutFlag = timeOutFlag;
		this.faultFlag = faultFlag;
		this.errorFlag = errorFlag;
		this.responseString = responseString;
		
	}
	
	public void run(){
		this.model.logResponseTime(requestType, tsSend, tsReceived, duration, threadNumber, timeOutFlag, faultFlag, errorFlag, responseString);
	}
}
