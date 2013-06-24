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
package wsattacker.plugin.dos.dosExtension.attackThreads;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.support.soap.SoapUtils;
import com.eviware.soapui.model.iface.Request;
import java.awt.EventQueue;
import java.util.EmptyStackException;
import java.util.Map;
import javax.xml.soap.SOAPException;
import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Node;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.plugin.dos.dosExtension.attackRunnables.LogRequestRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberNetworktestProbesRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberProbesRunnable;

import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberRequestsRunnable;
import wsattacker.plugin.dos.dosExtension.util.UtilDos;


import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;
import wsattacker.plugin.dos.dosExtension.requestSender.RequestSender;

/**
 * Send request to target depending on requestType 
 * various data regarding request gets logged
 *
 * @author af
 *
 */
public class SendRequestThread extends Thread {  // implements Oberservable Subject

    private AttackModel model; 		// Refernz auf Model -> hier syncronisieren!!
    private long timeStart;	// ms
    private long timeEnd;	// ms
    private long durationStart;	// ns
    private long durationEnd;	// ns
    private long duration;	// ns
    private int threadNumber;
    private boolean timeOutFlag = false;
    private boolean faultFlag = false;
    private boolean errorFlag = false;
    private String requestType;
    private String responseString = "";


    public SendRequestThread(AttackModel model, int threadNumber, String requestType) {

	this.model = model;
	this.threadNumber = threadNumber;
	this.requestType = requestType;

	// run Thread
	start();
    }

    // new Request is send ONCE and logged!
    public void run() {

	// Start time 
	timeStart = System.currentTimeMillis();
	durationStart = System.nanoTime();

	// do actual sending depending on requestType
	RequestSender requestSender = new RequestSender(model);
	if (this.requestType.equals("tampered")){
	    responseString = requestSender.sendTamperedRequest();
	}else if (this.requestType.equals("untampered")){
	    responseString = requestSender.sendUntamperedRequest();
	}else if (this.requestType.equals("testProbe")){
	    responseString = requestSender.sendTestProbeRequest();
	}else{
	    throw new EmptyStackException();
	}

	// Stop time
	timeEnd = System.currentTimeMillis();
	durationEnd = System.nanoTime();
	duration = durationEnd - durationStart;	
	
	// Check for empty Response or SOAP-Fault
	// - SOAP-Fault check by finding end of closing Tag "Fault>"
	if (responseString.length()==0) {
	    errorFlag = true;
	}else if(responseString.contains("Fault>")){ 
	    faultFlag = true;
	}


	// Log time -> done in context of EDT
	LogRequestRunnable log = new LogRequestRunnable(this.model, this.requestType, timeStart, timeEnd, duration, this.threadNumber, timeOutFlag, faultFlag, errorFlag, responseString);
	EventQueue.invokeLater(log);
	//System.out.println(this.requestType + "-Request of Thread " + this.threadNumber + ", in " + duration + " ns send");

	// Update GUI + Counter
	// - since called via runnable, Method will be executed in EDT -> no Problems with Syncronization!
	if (this.requestType.equals("tampered") || this.requestType.equals("untampered")) {
	    UpdateNumberRequestsRunnable update = new UpdateNumberRequestsRunnable(model, requestType);
	    EventQueue.invokeLater(update);
	} else if (this.requestType.equals("testProbe")) {
	    UpdateNumberProbesRunnable update = new UpdateNumberProbesRunnable(model);
	    EventQueue.invokeLater(update);
	} else if (this.requestType.equals("networkTest")) {
	    UpdateNumberNetworktestProbesRunnable update = new UpdateNumberNetworktestProbesRunnable(model);
	    EventQueue.invokeLater(update);
	}

	// Log completion
	Result.getGlobalResult().add(new ResultEntry(ResultLevel.Trace, getName(), "Done Sending "+this.requestType+"-Request in "+duration+" ns"));
    }
}
