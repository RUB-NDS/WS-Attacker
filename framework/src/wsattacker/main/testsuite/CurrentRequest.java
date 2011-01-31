/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010  Christian Mainka
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package wsattacker.main.testsuite;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.submit.transports.http.WsdlResponse;
import com.eviware.soapui.model.iface.Request.SubmitException;
import com.eviware.soapui.model.iface.Response;

import wsattacker.main.Preferences;
import wsattacker.main.composition.testsuite.CurrentOperationObserver;
import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.composition.testsuite.CurrentRequestObserver;
import wsattacker.main.composition.testsuite.RequestResponsePair;

/**
 * Holds a references to the currently used request
 * @author Christian Mainka
 *
 */
public class CurrentRequest implements PropertyChangeListener,
		CurrentOperationObserver, RequestResponsePair {
	private static Logger log = Logger.getLogger(CurrentRequest.class);
	public final static String BASICREQUSTNAME = "Basic Request";

	private List<CurrentRequestObserver> requestObservers;
	private List<CurrentRequestContentChangeObserver> contentObservers;
	private WsdlRequest currentRequest;
	private WsdlResponse currentResponse;
	TestSuite testsuite;

	public CurrentRequest(TestSuite testsuite) {
		this.requestObservers = new ArrayList<CurrentRequestObserver>();
		this.contentObservers = new ArrayList<CurrentRequestContentChangeObserver>();
		this.testsuite = testsuite;
		this.testsuite.getCurrentOperation().addCurrentOperationObserver(this);
		this.currentRequest = null;
		this.currentResponse = null;
	}

	public void addCurrentRequestObserver(CurrentRequestObserver o) {
		requestObservers.add(o);
	}

	public void removeCurrentRequestObserver(CurrentRequestObserver o) {
		requestObservers.remove(o);
	}

	public void notifyCurrentRequestObservers(WsdlRequest newRequest,
			WsdlRequest oldRequest) {
		if (newRequest == null) {
			for (CurrentRequestObserver o : requestObservers) {
				o.noCurrentRequest();
			}
		} else {
			for (CurrentRequestObserver o : requestObservers) {
				o.currentRequestChanged(newRequest, oldRequest);
			}
			// notifyCurrentRequestContentObservers(newRequest.getRequestContent(),
			// oldRequest.getRequestContent()); // is this really necessary?
		}
	}

	public void addCurrentRequestContentObserver(
			CurrentRequestContentChangeObserver o) {
		contentObservers.add(o);
	}

	public void removeCurrentRequestContentObserver(
			CurrentRequestContentChangeObserver o) {
		contentObservers.remove(o);
	}

	public void notifyCurrentRequestContentObservers(String newContent,
			String oldContent) {
		for (CurrentRequestContentChangeObserver o : contentObservers) {
			o.currentRequestContentChanged(newContent, oldContent);
		}
	}

	public WsdlRequest getWsdlRequest() {
		return currentRequest;
	}

	private void setWsdlRequest(WsdlRequest currentRequest) {
		WsdlRequest oldRequest = this.currentRequest;
		try {
			currentRequest.addPropertyChangeListener("request", this);
			log.info("Set Current Request Listener to" + currentRequest.getName());
			oldRequest.removePropertyChangeListener(this);
		} catch (Exception e) {
			// we are no listener or NULL Object
		}
		try {
			oldRequest.removePropertyChangeListener(this);
		} catch (Exception e) {
			// we are no listener or NULL Object
		}
		this.currentRequest = currentRequest;
		if (currentRequest != oldRequest) {
			notifyCurrentRequestObservers(currentRequest, oldRequest);
			this.currentResponse = null;
		}
	}

	public void setContent(String content) {
		currentRequest.setRequestContent(content);
	}
	
	public WsdlResponse getWsdlResponse() {
		return currentResponse;
	}
	
	public void submitRequest() throws SubmitException, NullPointerException {
		if(currentRequest == null) {
			throw new NullPointerException("There is no request to submit");
		}
		WsdlSubmit<WsdlRequest> submit;
		WsdlSubmitContext c = new WsdlSubmitContext(currentRequest);
		submit = (WsdlSubmit<WsdlRequest>) currentRequest.submit(c, false);
		Response response = submit.getResponse();
		if( response instanceof WsdlResponse) {
			currentResponse = (WsdlResponse) response;
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent arg0) {
		log.info("Current Request Content chaged!");
		notifyCurrentRequestContentObservers((String) arg0.getNewValue(),
				(String) arg0.getOldValue());
	}

	@Override
	public void currentOperationChanged(WsdlOperation newOperation,
			WsdlOperation oldOperation) {
		WsdlRequest request = newOperation.getRequestByName(BASICREQUSTNAME);
		if (request == null) {
			log.info("Creating basic request");
			request = newOperation.addNewRequest(BASICREQUSTNAME);
			String content = newOperation.createRequest(Preferences
					.getInstance().isCreateOtionalElements());
			log.trace("Content:\n" + content);
			request.setRequestContent(content);
		}
		setWsdlRequest(request);
	}

	@Override
	public void noCurrentOperation() {
		setWsdlRequest(null);
	}
}
