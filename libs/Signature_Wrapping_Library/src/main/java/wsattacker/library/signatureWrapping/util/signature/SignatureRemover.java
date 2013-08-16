/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
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
package wsattacker.library.signatureWrapping.util.signature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * Helper Class to remove an XML Signature from an XML message.
 */
public class SignatureRemover {

    Document doc;
    SignatureManager signatureManager;
    private String xmlWithoutSignature;

    /**
     * Constructor will throw an InvalidArgumentException in the following
     * cases:
     * 1) The argument is not valid XML
     * 2) The XML does not contain an XML Signature
     *
     * @param xml
     *
     * @throws InvalidArgumentException
     */
    public SignatureRemover(String xml) throws IllegalArgumentException {
        try {
            doc = DomUtilities.stringToDom(xml);
        } catch (SAXException ex) {
            throw new IllegalArgumentException("Could not Parse XML Document");
        }
        signatureManager = new SignatureManager();
        signatureManager.setDocument(doc);
        if (signatureManager.getSignatureElements().isEmpty()) {
            throw new IllegalArgumentException("XML Document does not contain any XML Signature");
        }

    }

    public SignatureRemover(Document xmlDoc) throws IllegalArgumentException {
        doc = DomUtilities.createNewDomFromNode(xmlDoc);
        signatureManager = new SignatureManager();
        signatureManager.setDocument(doc);
        if (signatureManager.getSignatureElements().isEmpty()) {
            throw new IllegalArgumentException("XML Document does not contain any XML Signature");
        }

    }

    /**
     * @return the xmlWithoutSignature
     */
    public String getXmlWithoutSignature() {
        // Lazy Evaluation: Create Message on first access
        if (xmlWithoutSignature == null) {
            // Remove every Signature Element
            for (SignatureElement signature : signatureManager.getSignatureElements()) {
                Element element = signature.getSignature();
                if (element.getParentNode() != null) {
                    element.getParentNode().removeChild(element);
                }
            }
            // Convert to String
            xmlWithoutSignature = DomUtilities.domToString(doc);
        }
        return xmlWithoutSignature;
    }

}
