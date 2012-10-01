/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2011 Christian Mainka
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
package wsattacker.plugin.signatureWrapping.option;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

import org.apache.log4j.Logger;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.logging.Level;
import org.w3c.dom.DOMException;
import org.xml.sax.SAXException;

import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOptionComplex;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.plugin.signatureWrapping.util.signature.ReferringElementInterface;

/**
 * The OptionPayload class hold gives a connection between the signed element and the payload element.
 */
public class OptionPayload extends AbstractOptionComplex
{
  private static Logger             log              = Logger.getLogger(OptionPayload.class);

  private static final long         serialVersionUID = 1L;
  private String                    value;
  private boolean                   isTimestamp;
  private Document                  originalDocument;
  private Element                   payloadElement, signedElement;
  private ReferringElementInterface referringElement;

  /**
   * Constructor for the OptionPayload.
   * @param referringElement : Reference to the Reference element.
   * @param name : Name of the option.
   * @param signedElement : The signed element. This is usefull, if the Reference element selects more than one signed element (e.g. when using XPath).
   * @param description . Description of the option.
   */
  public OptionPayload(ReferringElementInterface referringElement,
                       String name,
                       Element signedElement,
                       String description)
  {
    super(name, description);
    this.referringElement = referringElement;
    this.signedElement = signedElement;
    this.value = DomUtilities.domToString(signedElement);
    this.payloadElement = null;
    this.isTimestamp = this.signedElement.getLocalName().equals(WSConstants.TIMESTAMP_TOKEN_LN);
    
	
    try {
		this.originalDocument = DomUtilities.stringToDom(value);
    } catch (SAXException ex) {
		java.util.logging.Logger.getLogger(OptionPayload.class.getName()).log(Level.SEVERE, null, ex);
    }
    this.originalDocument.normalizeDocument();
  }

  /**
   * Does this option has any payload?
   * @return
   */
  public boolean hasPayload()
  {
// Document newDocument;
// try
// {
// newDocument = DomUtilities.stringToDom(value);
// }
// catch (Exception e)
// {
// // will never happen
// return false;
// }
// newDocument.normalizeDocument();
// return !originalDocument.isEqualNode(newDocument);
    return (payloadElement != null);
  }

  /**
   * Returns the payload element.
   * If it is a Timestamp element, automatically an updated one is returned.
   * @return the payload elemeent.
   * @throws InvalidPayloadException
   */
  public Element getPayloadElement() throws InvalidPayloadException
  {
    Element retr = payloadElement;
    // If it is a timestamp, we need to create a valid one!
    if (isTimestamp)
    {
      Element timestamp = (Element) originalDocument.getDocumentElement().cloneNode(true);
      // 1) Find created and expires Element
      // ////////////////////////////////////
      Element createdElement = null, expiresElement = null;
      for (Node cur = timestamp.getFirstChild(); cur != null; cur = cur.getNextSibling())
      {
        if (cur.getNodeType() == Node.ELEMENT_NODE)
        {
          // Case Created
          if (WSConstants.CREATED_LN.equals(cur.getLocalName()) && WSConstants.WSU_NS.equals(cur.getNamespaceURI()))
          {
            createdElement = (Element) cur;
          }
          // Case Exires
          else if (WSConstants.EXPIRES_LN.equals(cur.getLocalName()) && WSConstants.WSU_NS
              .equals(cur.getNamespaceURI()))
          {
            expiresElement = (Element) cur;
          }
        }
      }
      if (createdElement == null)
      {
        String warning = "Could not find Created Element in Timestamp";
        log.warn(warning);
        throw new InvalidPayloadException(warning);
      }
      if (expiresElement == null)
      {
        String warning = "Could not find Expires Element in Timestamp";
        log.warn(warning);
        throw new InvalidPayloadException(warning);
      }
      // 2) Detect if Timestamp uses milliseconds
      // /////////////////////////////////////////
      // milliseconds format contains a dot followed by the ms
      boolean inMilliseconds = (createdElement.getTextContent().indexOf('.') > 0 ? true : false);
      // 3) Create a Date formater
      // //////////////////////////
      DateFormat zulu = null;
      if (inMilliseconds)
      {
        zulu = new XmlSchemaDateFormat();
      }
      else
      {
        zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        zulu.setTimeZone(TimeZone.getTimeZone("UTC"));
      }
      // 3) Parse the dates
      // ///////////////////
      Calendar created = Calendar.getInstance();
      Calendar expires = Calendar.getInstance();
      try
      {
        created.setTime(zulu.parse(createdElement.getTextContent()));
        expires.setTime(zulu.parse(expiresElement.getTextContent()));
      }
      catch (Exception e)
      {
        String warning = "Timstamp is invalid formated";
        log.warn(warning);
        throw new InvalidPayloadException(warning);
      }
      // 4) Compute Difference = TTL
      // ////////////////////////////
      int diff = (int) ((expires.getTimeInMillis() - created.getTimeInMillis()) / 1000);
      // 5) Update Created/Expires according to detected format and TTL
      // ///////////////////////////////////////////////////////////////
      created = Calendar.getInstance();
      expires = Calendar.getInstance();
      expires.add(Calendar.SECOND, diff);
      // 6) Saves values in Elements
      // ////////////////////////////
      try {
      createdElement.setTextContent(zulu.format(created.getTime()));
      expiresElement.setTextContent(zulu.format(expires.getTime()));
      }
      catch (DOMException e) {
        String warning = "Could not parse time format\n" + e.getLocalizedMessage();
        log().error(warning);
        throw new InvalidPayloadException(warning);
      }
      retr = timestamp;
    }
    return retr;
  }
  
  /**
   * Return the signed element.
   * @return
   */
  public Element getSignedElement() {
    return signedElement;
  }

  /**
   * Return the Reference element.
   * @return
   */
  public ReferringElementInterface getReferringElement()
  {
    return referringElement;
  }

  /**
   * Is the signed element a Timestamp element?
   * @return
   */
  public boolean isTimestamp()
  {
    return isTimestamp;
  }

  /**
   * Set if the signed element is a Timestamp element.
   * @param isTimestamp
   */
  public void setTimestamp(boolean isTimestamp)
  {
    log().trace(getName() + " setTimestamp = " + isTimestamp);
    this.isTimestamp = isTimestamp;
  }

  private Logger log()
  {
    return Logger.getLogger(getClass());
  }

  @Override
  public boolean isValid(String value)
  {
    boolean isValid = true;
    if (value.length() >= 3) {
		try
		{
		  DomUtilities.stringToDom(value);
		}
		catch (Exception e)
		{
		  log().error(getName() + ": " + "Error: " + e.getLocalizedMessage());
		  isValid = false;
		}
	}
    return isValid;
  }

  /**
   * Returns the GUI component for the OptionPayload used by the WS-Attacker.
   */
  @Override
  public AbstractOptionGUI getComplexGUI(ControllerInterface controller,
                                         AbstractPlugin plugin)
  {
    log().trace(getName() + ": " + "GUI Requested");
    return new OptionPayloadGUI(controller, plugin, this);
  }

  /**
   * The the value for the payload.
   */
  @Override
  public boolean parseValue(String value)
  {
    if (isValid(value))
    {
      try
      {
        Document newPayloadDoc = DomUtilities.stringToDom(value);
        newPayloadDoc.normalizeDocument();
        if (!originalDocument.isEqualNode(newPayloadDoc))
        {
          this.payloadElement = newPayloadDoc.getDocumentElement();
        }
        else
        {
          this.payloadElement = null;
        }
      }
      catch (Exception e)
      {
        e.printStackTrace();
        return false;
      }
      this.value = value;
      notifyValueChanged();
      log().info("Has payload? " + hasPayload());
      return true;
    }
    return false;
  }

  @Override
  public String getValueAsString()
  {
    return value;
  }

}
