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
package wsattacker.library.signatureWrapping.util.signature.weakness;

import java.util.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.namespace.NamespaceConstants.URI_NS_DS;
import static wsattacker.library.xmlutilities.namespace.NamespaceConstants.URI_NS_SAML20;
import static wsattacker.library.xmlutilities.namespace.NamespaceConstants.URI_NS_SAML20P;

/**
 *
 * @author christian
 */
public class SignatureManipulationHelperTest {

    public static Document generateDummySamlDocument(boolean signedResponse, boolean signedAssertion, boolean prepend) {
        Document doc = DomUtilities.createDomDocument();
        Element response = doc.createElementNS(URI_NS_SAML20P, "samlp:Response");
        doc.appendChild(response);
        Element assertion = doc.createElementNS(URI_NS_SAML20, "saml:Assertion");
        response.appendChild(assertion);
        if (signedResponse) {
            Element sig = doc.createElementNS(URI_NS_DS, "ds:Signature");
            if (prepend) {
                response.insertBefore(sig, assertion);
            } else {
                response.appendChild(sig);
            }
        }
        if (signedAssertion) {
            Element sig = doc.createElementNS(URI_NS_DS, "ds:Signature");
            assertion.appendChild(sig);
        }
        return doc;
    }

    @Test
    public void testDoubleSignature() {
    }

    @Test
    public void testRemoveSignature_one_contained() {
        Document doc = generateDummySamlDocument(true, false, false);
        Element sig = (Element) doc.getDocumentElement().getLastChild();
        List<Element> sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(1, sigList.size());

        SignatureManipulationHelper.removeSignature(doc, 0);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertTrue(sigList.isEmpty());
    }

    @Test
    public void testRemoveSignature_0_two_contained() {
        Document doc = generateDummySamlDocument(true, true, false);
        Element sig = (Element) doc.getDocumentElement().getLastChild();
        List<Element> sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(2, sigList.size());

        SignatureManipulationHelper.removeSignature(doc, 0);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(1, sigList.size());
        assertEquals("Assertion", sigList.get(0).getParentNode().getLocalName());

        SignatureManipulationHelper.removeSignature(doc, 0);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertTrue(sigList.isEmpty());
    }

    @Test
    public void testRemoveSignature_1_two_contained() {
        Document doc = generateDummySamlDocument(true, true, false);
        Element sig = (Element) doc.getDocumentElement().getLastChild();
        List<Element> sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(2, sigList.size());

        SignatureManipulationHelper.removeSignature(doc, 1);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(1, sigList.size());
        assertEquals("Response", sigList.get(0).getParentNode().getLocalName());

        SignatureManipulationHelper.removeSignature(doc, 0);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertTrue(sigList.isEmpty());
    }

    @Test
    public void testRemoveSignature_0_two_contained_prepended() {
        Document doc = generateDummySamlDocument(true, true, true);
        Element sig = (Element) doc.getDocumentElement().getLastChild();
        List<Element> sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(2, sigList.size());

        SignatureManipulationHelper.removeSignature(doc, 0);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(1, sigList.size());
        assertEquals("Assertion", sigList.get(0).getParentNode().getLocalName());

        SignatureManipulationHelper.removeSignature(doc, 0);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertTrue(sigList.isEmpty());
    }

    @Test
    public void testRemoveSignature_1_two_contained_prepended() {
        Document doc = generateDummySamlDocument(true, true, true);
        Element sig = (Element) doc.getDocumentElement().getLastChild();
        List<Element> sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(2, sigList.size());

        SignatureManipulationHelper.removeSignature(doc, 1);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertEquals(1, sigList.size());
        assertEquals("Response", sigList.get(0).getParentNode().getLocalName());

        SignatureManipulationHelper.removeSignature(doc, 0);
        sigList = DomUtilities.findChildren(doc.getDocumentElement(), "Signature", URI_NS_DS, true);
        assertTrue(sigList.isEmpty());
    }
}
