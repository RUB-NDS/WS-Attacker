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
package wsattacker.library.signatureWrapping.xpath.weakness;

import java.util.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.util.KeyInfoForTesting;
import wsattacker.library.signatureWrapping.util.Signer;
import wsattacker.library.signatureWrapping.util.SoapTestDocument;
import wsattacker.library.signatureWrapping.util.dom.DomUtilities;
import wsattacker.library.signatureWrapping.util.signature.NamespaceConstants;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.signatureWrapping.xpath.wrapping.WrappingOracle;

public class XPathNamespaceInjectionWeaknessTest {

    @Test
    public void simpleTestBefore() throws Exception {
        SoapTestDocument soap = new SoapTestDocument();

        String orgContent = "ORIGINAL CONTENT";
        String atkContent = "ATTACKER CONTENT";

        Document doc = soap.getDocument();

        Element signed = soap.getDummyPayloadBody();
        signed = (Element) signed.appendChild(doc.createElementNS(soap.getDummyPayloadBody().getNamespaceURI(), "ns1:signed"));
        signed = (Element) signed.appendChild(doc.createElementNS("http://test-ns", "ts:test"));
        signed.setTextContent(orgContent);

        String xpath = DomUtilities.getFastXPath(signed);
        List<String> toSign = new ArrayList<String>();
        toSign.add(xpath);

        Signer s = new Signer(new KeyInfoForTesting());
        s.sign(soap.getDocument(), toSign);

        SignatureManager sm = new SignatureManager();
        sm.setDocument(doc);

        List<Payload> payloadList = sm.getPayloads();

        payloadList.get(0).setValue(payloadList.get(0).getValue().replace(orgContent, atkContent));

        WrappingOracle wo = new WrappingOracle(doc, payloadList, new SchemaAnalyzer());

        assertEquals(9 * 2 * 3, wo.maxPossibilities());

        List<Element> bodyChilds;
        bodyChilds = DomUtilities.getAllChildElements(soap.getBody());
        assertEquals(1, bodyChilds.size());

        String docBefore = DomUtilities.domToString(doc);

        Document attackDocument = wo.getPossibility(9 * 2 * 1 + 4);

        String docAfter = DomUtilities.domToString(doc);
        assertEquals("Original document must be unchanged", docBefore, docAfter);

        String xml = DomUtilities.domToString(attackDocument, true);
        System.out.println(xml);
        System.out.println(WeaknessLog.representation());

        bodyChilds = DomUtilities.getAllChildElements(DomUtilities.findCorrespondingElement(attackDocument, soap.getBody()));
        assertEquals(2, bodyChilds.size());

        int orgPos = xml.indexOf(orgContent);
        int atkPos = xml.indexOf(atkContent);
        assertTrue(orgPos > 0);
        assertTrue(atkPos > 0);
        assertTrue(atkPos < orgPos);

        assertEquals("atkns1", bodyChilds.get(1).getPrefix());
        assertEquals("ns1", bodyChilds.get(0).getPrefix());

        assertEquals(NamespaceConstants.URI_NS_WSATTACKER, DomUtilities.findChildren(attackDocument, "Transform", NamespaceConstants.URI_NS_DS, true).get(0).getAttribute("xmlns:ns1"));
    }
}
