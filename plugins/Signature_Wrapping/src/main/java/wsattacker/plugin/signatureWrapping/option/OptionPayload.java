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
package wsattacker.plugin.signatureWrapping.option;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.signature.ReferringElementInterface;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOptionComplex;

/**
 * The OptionPayload class hold gives a connection between the signed element
 * and the payload element.
 */
public class OptionPayload extends AbstractOptionComplex {

	private static Logger log = Logger.getLogger(OptionPayload.class);
	private Payload payload;

	/**
	 * Constructor for the OptionPayload.
	 *
	 * @param referringElement : Reference to the Reference element.
	 * @param name : Name of the option.
	 * @param signedElement : The signed element. This is usefull, if the
	 * Reference element selects more than one signed element (e.g. when using
	 * XPath).
	 * @param description . Description of the option.
	 */
	public OptionPayload(Payload payload) {
		super(payload.getName(), payload.getDescription());
		this.payload = payload;
	}

	/**
	 * Does this option has any payload?
	 *
	 * @return
	 */
	public boolean hasPayload() {
		return payload.hasPayload();
	}

	/**
	 * Returns the payload element.
	 * If it is a Timestamp element, automatically an updated one is returned.
	 *
	 * @return the payload elemeent.
	 * @throws InvalidPayloadException
	 */
	public Element getPayloadElement() throws InvalidPayloadException {
		return payload.getPayloadElement();
	}

	/**
	 * Return the signed element.
	 *
	 * @return
	 */
	public Element getSignedElement() {
		return payload.getSignedElement();
	}

	/**
	 * Return the Reference element.
	 *
	 * @return
	 */
	public ReferringElementInterface getReferringElement() {
		return payload.getReferringElement();
	}

	/**
	 * Is the signed element a Timestamp element?
	 *
	 * @return
	 */
	public boolean isTimestamp() {
		return payload.isTimestamp();
	}

	/**
	 * Set if the signed element is a Timestamp element.
	 *
	 * @param isTimestamp
	 */
	public void setTimestamp(boolean isTimestamp) {
		payload.setTimestamp(isTimestamp);
	}

	private Logger log() {
		return Logger.getLogger(getClass());
	}

	@Override
	public boolean isValid(String value) {
		return payload.isValid(value);
	}

	/**
	 * Returns the GUI component for the OptionPayload used by the WS-Attacker.
	 */
	@Override
	public AbstractOptionGUI getComplexGUI(ControllerInterface controller,
	  AbstractPlugin plugin) {
		log().trace(getName() + ": " + "GUI Requested");
		return new OptionPayloadGUI(controller, plugin, this);
	}

	/**
	 * The the value for the payload.
	 */
	@Override
	public boolean parseValue(String value) {
		boolean isValid = isValid(value);
		if (isValid) {
			payload.setValue(value);
		}
		return isValid;
	}

	@Override
	public String getValueAsString() {
		return payload.getValue();
	}
}
