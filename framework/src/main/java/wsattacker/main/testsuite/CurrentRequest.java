/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.main.testsuite;

import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.submit.transports.http.WsdlResponse;
import com.eviware.soapui.model.iface.Request.SubmitException;
import com.eviware.soapui.model.iface.Response;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.jdesktop.beans.AbstractBean;
import wsattacker.main.Preferences;
import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.composition.testsuite.CurrentRequestObserver;
import wsattacker.main.composition.testsuite.RequestResponsePair;

/**
 * Holds a references to the currently used request
 *
 * @author Christian Mainka
 *
 */
public class CurrentRequest extends AbstractBean implements PropertyChangeListener, RequestResponsePair {

	final private static Logger LOG = Logger.getLogger(CurrentRequest.class);
	final public static String BASICREQUSTNAME = "Basic Request";
	public static final String PROP_WSDLREQUESTCONTENT = "wsdlRequestContent";
	public static final String PROP_WSDLRESPONSECONTENT = "wsdlResponseContent";
	public static final String PROP_WSDLREQUEST = "wsdlRequest";
	public static final String PROP_WSDLRESPONSE = "wsdlResponse";
	private static final String PROP_SOAPUI_REQUEST_CONTENT = "request";
	private WsdlRequest wsdlRequest;
	private WsdlResponse wsdlResponse;
	private CurrentOperation currentOperation;
	final private List<CurrentRequestObserver> requestObservers = new ArrayList<CurrentRequestObserver>();
	final private List<CurrentRequestContentChangeObserver> contentObservers = new ArrayList<CurrentRequestContentChangeObserver>();

	public CurrentRequest() {
	}

	public CurrentOperation getCurrentOperation() {
		return currentOperation;
	}

	public void setCurrentOperation(CurrentOperation newCurrentOperation) {
		final CurrentOperation oldOperation = this.currentOperation;
		if (oldOperation != null) {
			oldOperation.removePropertyChangeListener(this);
		}
		this.currentOperation = newCurrentOperation;
		if (newCurrentOperation != null) {
			newCurrentOperation.addPropertyChangeListener(CurrentOperation.PROP_WSDLOPERATION, this);
		}
	}

	/**
	 * Get the value of wsdlRequest
	 *
	 * @return the value of wsdlRequest
	 */
	public WsdlRequest getWsdlRequest() {
		return wsdlRequest;
	}

	/**
	 * Set the value of wsdlRequest
	 *
	 * @param newWsdlRequest new value of wsdlRequest
	 */
	public void setWsdlRequest(WsdlRequest newWsdlRequest) {
		WsdlRequest oldWsdlRequest = this.wsdlRequest;
		String oldWsdlRequestContent = "";
		if (oldWsdlRequest != null) {
			oldWsdlRequest.removePropertyChangeListener(PROP_SOAPUI_REQUEST_CONTENT, this);
			oldWsdlRequestContent = oldWsdlRequest.getRequestContent();
		}
		if (newWsdlRequest != null) {
			newWsdlRequest.addPropertyChangeListener(PROP_SOAPUI_REQUEST_CONTENT, this);
		}
		this.wsdlRequest = newWsdlRequest;
		String newWsdlRequestContent = getWsdlRequestContent();
		firePropertyChange(PROP_WSDLREQUEST, oldWsdlRequest, newWsdlRequest);
		firePropertyChange(PROP_WSDLREQUESTCONTENT, oldWsdlRequestContent, newWsdlRequestContent);
		notifyCurrentRequestObservers(newWsdlRequest, oldWsdlRequest);
		notifyCurrentRequestContentObservers(newWsdlRequestContent, oldWsdlRequestContent);
	}

	/**
	 * Get the value of wsdlResponse
	 *
	 * @return the value of wsdlResponse
	 */
	public WsdlResponse getWsdlResponse() {
		return wsdlResponse;
	}

	/**
	 * Set the value of wsdlResponse
	 *
	 * @param newWsdlResponse new value of wsdlResponse
	 */
	public void setWsdlResponse(WsdlResponse newWsdlResponse) {
		WsdlResponse oldWsdlResponse = this.wsdlResponse;
		String oldWsdlResponseContent = getWsdlResponseContent();
		this.wsdlResponse = newWsdlResponse;
		String newWsdlResponseContent = getWsdlResponseContent();
		firePropertyChange(PROP_WSDLRESPONSE, oldWsdlResponse, newWsdlResponse);
		firePropertyChange(PROP_WSDLRESPONSECONTENT, oldWsdlResponseContent, newWsdlResponseContent);
	}

	/**
	 * Get the value of wsdlResponseContent
	 *
	 * @return the value of wsdlResponseContent
	 */
	public String getWsdlResponseContent() {
		final String wsdlResponseContent;
		if (wsdlResponse != null) {
			wsdlResponseContent = wsdlResponse.getContentAsString();
		} else {
			wsdlResponseContent = "";
		}
		return wsdlResponseContent;
	}

	/**
	 * Get the value of wsdlRequestContent
	 *
	 * @return the value of wsdlRequestContent
	 */
	public String getWsdlRequestContent() {
		final String wsdlRequestContent;
		if (wsdlRequest != null) {
			wsdlRequestContent = wsdlRequest.getRequestContent();
		} else {
			wsdlRequestContent = "";
		}
		return wsdlRequestContent;
	}

	/**
	 * Set the value of wsdlRequestContent
	 *
	 * @param wsdlRequestContent new value of wsdlRequestContent
	 */
	public void setWsdlRequestContent(String wsdlRequestContent) {
		if (wsdlRequest != null) {
			wsdlRequest.setRequestContent(wsdlRequestContent);
		}
	}

	public void submitRequest() throws SubmitException, NullPointerException {
		if (wsdlRequest == null) {
			throw new NullPointerException("There is no request to submit");
		}
		WsdlSubmit<WsdlRequest> submit;
		WsdlSubmitContext c = new WsdlSubmitContext(wsdlRequest);
		submit = (WsdlSubmit<WsdlRequest>) wsdlRequest.submit(c, false);
		Response response = submit.getResponse();
		if (response instanceof WsdlResponse) {
			setWsdlResponse((WsdlResponse) response);
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent pce) {
		final String propName = pce.getPropertyName();
		if (CurrentOperation.PROP_WSDLOPERATION.equals(propName)) {
			LOG.info("Detected Operation change");
			final WsdlOperation wsdlOperation = (WsdlOperation) pce.getNewValue();
			WsdlRequest request = null;
			if (wsdlOperation != null) {
				request = wsdlOperation.getRequestByName(BASICREQUSTNAME);
				if (request == null) {
					LOG.info("Creating basic request");
					request = wsdlOperation.addNewRequest(BASICREQUSTNAME);
					String content = wsdlOperation.createRequest(Preferences
						.getInstance().isCreateOtionalElements());
					LOG.trace("Content:\n" + content);
					request.setRequestContent(content);
				}
			}
			setWsdlRequest(request);
		} else if (PROP_SOAPUI_REQUEST_CONTENT.equals(propName)) {
			LOG.info("Current Request Content chaged!");
			final String newValue = (String) pce.getNewValue();
			final String oldValue = (String) pce.getOldValue();
			firePropertyChange(PROP_WSDLREQUESTCONTENT, oldValue, newValue);
			notifyCurrentRequestContentObservers(newValue, oldValue);
		}
	}

	@Deprecated
	/**
	 * This method will be removed in future version. Use the
	 * propertyChangeSupport instead.
	 */
	public void addCurrentRequestObserver(CurrentRequestObserver o) {
		requestObservers.add(o);
	}

	@Deprecated
	/**
	 * This method will be removed in future version. Use the
	 * propertyChangeSupport instead.
	 */
	public void removeCurrentRequestObserver(CurrentRequestObserver o) {
		requestObservers.remove(o);
	}

	@Deprecated
	/**
	 * This method will be removed in future version. Use the
	 * propertyChangeSupport instead.
	 */
	private void notifyCurrentRequestObservers(WsdlRequest newRequest,
		WsdlRequest oldRequest) {
		if (oldRequest != newRequest) {
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
	}

	@Deprecated
	/**
	 * This method will be removed in future version. Use the
	 * propertyChangeSupport instead.
	 */
	public void addCurrentRequestContentObserver(
		CurrentRequestContentChangeObserver o) {
		contentObservers.add(o);
	}

	@Deprecated
	/**
	 * This method will be removed in future version. Use the
	 * propertyChangeSupport instead.
	 */
	public void removeCurrentRequestContentObserver(
		CurrentRequestContentChangeObserver o) {
		contentObservers.remove(o);
	}

	@Deprecated
	/**
	 * This method will be removed in future version. Use the
	 * propertyChangeSupport instead.
	 */
	private void notifyCurrentRequestContentObservers(String newContent,
		String oldContent) {
		for (CurrentRequestContentChangeObserver o : contentObservers) {
			o.currentRequestContentChanged(newContent, oldContent);
		}
	}
}
