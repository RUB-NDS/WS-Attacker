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
package wsattacker.plugin.signatureWrapping.util.signature;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.findChildren;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.getFirstChildElement;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_WSSE_1_0;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_WSSE_1_1;

/**
 * This class defines which parts of an XML Document is signed. For this
 * concrete use-case, it searches for a WS-Security Header element which
 * contains a Signature child. The Reference elements are then accessable.
 */
public class SignatureManager {

  private Document doc;
  private List<SignatureElement> sigList;

  public SignatureManager() {
    sigList = new ArrayList<SignatureElement>();
  }

  /**
   * Sets the current working Document.
   *
   * @param doc
   */
  public void setDocument(Document doc) {
    this.doc = doc;
    eval();
  }

  /**
   * Gets the current working Document.
   *
   * @return
   */
  public Document getDocument() {
    return doc;
  }

  /**
   * Returns the Signature Element Node
   *
   * @return
   */
  public List<SignatureElement> getSignatureElements() {
    return sigList;
  }

  private Logger log() {
    return Logger.getLogger(getClass());
  }

  private synchronized void eval() {
    sigList.clear();
    if (doc != null) {
      List<Element> signatureList = new ArrayList<Element>();
      try {
        signatureList = DomUtilities.evaluateXPath(doc, "//*[local-name()='Signature' and namespace-uri()='" + NamespaceConstants.URI_NS_DS + "']");
      } catch (XPathExpressionException ex) {
        log().error("Could not find any ds:Signature Elements.");
      }
      for (Element signature : signatureList) {
        log().trace("Found Signature Element " + DomUtilities.getFastXPath(signature));
        sigList.add(new SignatureElement(signature));
      }
    }
  }

  /**
   * Processes the Document - Searches for References - Searches for XPath
   * Expressions
   *
   * @return
   */
  /*
   * Old Method: Uses "Schema"
   *             -> /soapenv:Envelope[1]/soapenv:Header[1]/wsse:Security[1]/Assertion[1]/ds:Signature[1]
   private synchronized void eval() {
   sigList.clear();
   if (doc == null) {
   return; // nothing to do
   }
   // log().debug("Verifying Document:\n" +
   // SoapUtilities.domToString(doc));
   // Element sigElement =
   // getFirstChildElement(getFirstChildElement(getFirstChildElement(doc.getDocumentElement())));
   Element envelope = doc.getDocumentElement();
   // Element envelope = getFirstChildElement(doc);
   Element header = getFirstChildElement(envelope);

   // Search for WS Security Header
   List<Element> securityList = findChildren(header, "Security", URI_NS_WSSE_1_0);
   if (securityList.size() != 1) {
   securityList = findChildren(header, "Security", URI_NS_WSSE_1_1);
   if (securityList.size() < 1) {
   log().warn("Could not find WS Security Header");
   return;
   } else if (securityList.size() > 1) {
   log().warn("Message has more than one WS Security Header");
   return;
   }
   }
   // WS Security Header can contain ds:Signature Element children
   Element securityElement = securityList.get(0);
   List<Element> signatureParentList = new ArrayList<Element>();
   signatureParentList.add(securityElement);


   // Search for SAML Assertion
   List<Element> assertionList = findChildren(securityElement, "Assertion", null); // TODO: Use SAML Namespace?
   for (Element assertion : assertionList) {
   signatureParentList.add(assertion);
   }

   for (Element signatureParent : signatureParentList) {
   List<Element> signatureList = findChildren(signatureParent, "Signature", XMLSignature.XMLNS);
   for (Element signature : signatureList) {
   log().trace("Found Signature Element " + DomUtilities.getFastXPath(signature));
   sigList.add(new SignatureElement(signature));
   }
   }
   }
   */
  /**
   * Get a List of all PayloadOptions. Each PayloadOption referres to the
   * original Signed Content and additional contains the Payload to use for the
   * attack.
   *
   * @return List of all PayloadOptions
   */
  public List<OptionPayload> getPayloads() {
    List<OptionPayload> payloads = new ArrayList<OptionPayload>();
    for (SignatureElement signature : getSignatureElements()) {
      for (ReferenceElement ref : signature.getReferences()) {
        if (ref.getPayload() != null) {
          payloads.add(ref.getPayload());
        } else {
          for (XPathElement xpath : ref.getXPaths()) {
            for (OptionPayload option : xpath.getPayloads()) {
              payloads.add(option);
            }
          }
        }
      }
    }
    return payloads;
  }
}
