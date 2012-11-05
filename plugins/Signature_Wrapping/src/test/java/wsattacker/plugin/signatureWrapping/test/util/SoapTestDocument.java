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
package wsattacker.plugin.signatureWrapping.test.util;

import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.PREFIX_NS_DS;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.PREFIX_NS_SOAP_1_1_ENVELOPE;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.PREFIX_NS_SOAP_1_2_ENVELOPE;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.PREFIX_NS_WSSE;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.PREFIX_NS_WSU;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_DS;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_SOAP_1_1_ENVELOPE;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_SOAP_1_2_ENVELOPE;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_WSSE_1_0;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_WSU;

import java.util.List;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.Timestamp;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

/**
 * A simple SoapMessage Test document
 *
 */
public class SoapTestDocument
{
  Document doc;
  String   version;
  String   soapPrefix = "soap";
  Element  envelope;

  public SoapTestDocument()
  {
    this(URI_NS_SOAP_1_1_ENVELOPE);
  }

  public SoapTestDocument(String soapURI)
  {
    if (soapURI.equals(URI_NS_SOAP_1_2_ENVELOPE))
    {
      version = URI_NS_SOAP_1_2_ENVELOPE;
      soapPrefix = PREFIX_NS_SOAP_1_2_ENVELOPE;
    }
    else
    {
      version = URI_NS_SOAP_1_1_ENVELOPE;
      soapPrefix = PREFIX_NS_SOAP_1_1_ENVELOPE;
    }
    doc = DomUtilities.createDomDocument();
    envelope = doc.createElementNS(version, soapPrefix + ":Envelope");
    // create Envelope
    doc.appendChild(envelope);
    // create Header and Body
    getHeader();
    getBody();
  }

  public Document getDocument()
  {
    return doc;
  }

  public Element getOrCreateChild(Element parent,
                                  String name,
                                  String prefix,
                                  String uri)
  {
    List<Element> children = DomUtilities.findChildren(parent, name, uri);
    if (children.size() > 0) {
		  return (Element) children.get(0);
	  }
    Element newNode = parent.getOwnerDocument().createElementNS(uri, prefix + ":" + name);
    parent.appendChild(newNode);
    return newNode;
  }

  public Attr getOrCreateAttribute(Element ele,
                                   String name,
                                   String prefix,
                                   String uri,
                                   String value)
  {
    Attr a = ele.getAttributeNodeNS(uri, name);
    if (null == a)
    {
      // Add the Id Attribute
      a = doc.createAttributeNS(uri, prefix + ":" + name);
      a.setValue(value);
      ele.setAttributeNode(a);
    }
    return a;
  }

  public Element getEnvelope()
  {
    return envelope;
  }

  public Element getHeader()
  {
    return getOrCreateChild(getEnvelope(), "Header", soapPrefix, version);
  }

  public Element getBody()
  {
    return getOrCreateChild(getEnvelope(), "Body", soapPrefix, version);
  }

  public Element getSucurity()
  {
    return getOrCreateChild(getHeader(), "Security", PREFIX_NS_WSSE, URI_NS_WSSE_1_0);
  }

  public Element getTimestamp()
  {
    return getOrCreateChild(getSucurity(), "Timestamp", PREFIX_NS_WSU, URI_NS_WSU);
  }

  public void setTimestamp() {
    setTimestamp(false, true); // TTL=15min
  }

  public void setTimestamp(boolean expired, boolean inMilliseconds)
  {
    final String id = "timestampID";
    String ms = (inMilliseconds?".100":"");
    Element oldTimestamp = getTimestamp();


    Timestamp newTimestamp = null;
    if(expired) {
      final String old = "<wsu:Timestamp xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"+id+\"><wsu:Created>2011-11-28T21:01:12"+ms+"Z</wsu:Created><wsu:Expires>2011-11-28T21:06:12"+ms+"Z</wsu:Expires></wsu:Timestamp>";
      try
      {
        Element element = DomUtilities.stringToDom(old).getDocumentElement();
        Element importedElement = (Element) oldTimestamp.getOwnerDocument().importNode(element, true);
        newTimestamp = new Timestamp(importedElement);
      }
      catch (WSSecurityException e)
      {
        // Will never happen
        e.printStackTrace();
      }
      catch (SAXException e)
      {
        // Will never happen
        e.printStackTrace();
      }
    }
    else {
      final int TTL = 15*60; // TTL=15min
      newTimestamp = new Timestamp(true, doc, TTL);
      getOrCreateAttribute(getDummyPayloadHeader(), "Id", PREFIX_NS_WSU, URI_NS_WSU, id);
    }
    oldTimestamp.getParentNode().replaceChild(newTimestamp.getElement(), oldTimestamp);
  }

  public String getTimestampWsuId()
  {
    final String id = "timestampID";
    return getOrCreateAttribute(getTimestamp(), "Id", PREFIX_NS_WSU, URI_NS_WSU, id).getValue();
  }

  public Element getSignature()
  {
    return getOrCreateChild(getSucurity(), "Signature", PREFIX_NS_DS, URI_NS_DS);
  }

  public Element getDummyPayloadBody()
  {
    return getOrCreateChild(getBody(), "payloadBody", "ns1", "http://ns1-payload");
  }

  public String getDummyPayloadBodyWsuId()
  {
    final String id = "bodyToSign";
    return getOrCreateAttribute(getDummyPayloadBody(), "Id", PREFIX_NS_WSU, URI_NS_WSU, id).getValue();
  }

  public Element getDummyPayloadHeader()
  {
    return getOrCreateChild(getHeader(), "payloadHeader", "ns1", "http://ns1-payload");
  }

  public String getDummyPayloadHeaderWsuId()
  {
    String id = "headerToSign";
    return getOrCreateAttribute(getDummyPayloadHeader(), "Id", PREFIX_NS_WSU, URI_NS_WSU, id).getValue();
  }

  @Override
  public String toString()
  {
    return DomUtilities.domToString(doc, true);
  }

}
