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
import static org.junit.Assert.assertFalse;
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
public class PrefixRewriterTest {

    public static Element generatePayloadElementOfDummySamlDocument() {
        Document doc = DomUtilities.createDomDocument();
        Element response = doc.createElementNS(URI_NS_SAML20P, "samlp:Response");
        doc.appendChild(response);

        response.appendChild(doc.createElementNS(URI_NS_SAML20P, "samlp:Status"));
        response.appendChild(doc.createElementNS(URI_NS_SAML20P, "samlp:Irgendwas"));

        Element responseCopy = (Element) response.cloneNode(true);

        Element assertion = doc.createElementNS(URI_NS_SAML20, "saml:Assertion");
        response.appendChild(assertion);

        Element sigResp = doc.createElementNS(URI_NS_DS, "ds:Signature");
        response.insertBefore(sigResp, assertion);
        Element sigAss = doc.createElementNS(URI_NS_DS, "ds:Signature");
        assertion.appendChild(sigAss);

        sigAss.appendChild(responseCopy);
        return responseCopy;
    }

    @Test
    public void testRewritePrefix() {
        Document saml = generatePayloadElementOfDummySamlDocument().getOwnerDocument();
        String docString = DomUtilities.domToString(saml, true);

        assertFalse(docString.contains("<xyz:"));
        assertTrue(docString.contains("<samlp:"));

        PrefixRewriter.rewritePrefix(saml.getDocumentElement(), "samlp", "xyz");
        docString = DomUtilities.domToString(saml, true);
        assertTrue(docString.contains("<xyz:"));
        assertFalse(docString.contains("<samlp:"));
    }

    @Test
    public void testRewritePrefix_with_untouched_Elements() {
        Element payload = generatePayloadElementOfDummySamlDocument();
        Document saml = payload.getOwnerDocument();
        String docString = DomUtilities.domToString(saml, true);

        assertFalse(docString.contains("<xyz:"));
        assertTrue(docString.contains("<samlp:"));

        List<Element> untouchedList = new ArrayList<Element>(1);
        untouchedList.add(payload);
        PrefixRewriter.rewritePrefix(saml.getDocumentElement(), "samlp", "xyz", untouchedList);

        System.out.println("### Final:");
        System.out.println(DomUtilities.domToString(saml, true));

        String payloadString = DomUtilities.domToString(payload, true);
        assertFalse(payloadString.contains("<xyz:"));
        assertTrue(payloadString.contains("<samlp:"));

        // remove the payload
        payload.getParentNode().removeChild(payload);

        docString = DomUtilities.domToString(saml, true);
        assertTrue(docString.contains("<xyz:"));
        assertFalse(docString.contains("<samlp:"));
    }
}
