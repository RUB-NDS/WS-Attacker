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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.library.xmlutilities.dom;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author christian
 */
public class DomUtilitiesTest {

    private static final String PATH_TO_XML = "src/test/resources/example_signed_message.xml";

    public DomUtilitiesTest() {
    }

    @Test
    public void testCorrespondingElement() throws Exception {
        Document cmpDoc, newDoc;
        Element cmpElement, newElement;
        String cmpXPath, newXPath;

        // Security: Depth = 1
        cmpDoc = DomUtilities.readDocument(PATH_TO_XML);
        cmpElement = DomUtilities.getFirstChildElementByNames(cmpDoc.getDocumentElement(), "Header", "Security");
        cmpXPath = DomUtilities.getFastXPath(cmpElement);

        newDoc = DomUtilities.readDocument(PATH_TO_XML);

        newElement = DomUtilities.findCorrespondingElement(newDoc, cmpElement);
        newXPath = DomUtilities.getFastXPath(newElement);
        assertEquals(cmpXPath, newXPath);
        assertNotSame(cmpElement.getOwnerDocument(), newElement.getOwnerDocument());

        // SIgnature: Depth = 2;
        cmpDoc = DomUtilities.readDocument(PATH_TO_XML);
        cmpElement = DomUtilities.getFirstChildElementByNames(cmpDoc.getDocumentElement(), "Header", "Security", "Signature");
        cmpXPath = DomUtilities.getFastXPath(cmpElement);

        newDoc = DomUtilities.readDocument(PATH_TO_XML);

        newElement = DomUtilities.findCorrespondingElement(newDoc, cmpElement);
        newXPath = DomUtilities.getFastXPath(newElement);
        assertEquals(cmpXPath, newXPath);
        assertNotSame(cmpElement.getOwnerDocument(), newElement.getOwnerDocument());

    }

    @Test
    public void getNamespaceTest1() throws Exception {
        String xml;
        Document doc;
        Element b;
        xml = "<ns1:a xmlns:ns1=\"uri-ns1\"><ns1:b/></ns1:a>";
        doc = DomUtilities.stringToDom(xml);
        b = (Element) doc.getDocumentElement().getFirstChild();

        assertEquals("b", b.getLocalName());
        assertEquals("uri-ns1", b.getNamespaceURI());
        assertEquals("uri-ns1", DomUtilities.getNamespaceURI(b, "ns1"));
    }

    @Test
    public void getNamespaceTest2() throws Exception {
        String xml;
        Document doc;
        Element b;
        xml = "<ns1:a xmlns:ns1=\"uri-ns1\" xmlns:ns2=\"uri-ns2\"><ns1:b/></ns1:a>";
        doc = DomUtilities.stringToDom(xml);
        b = (Element) doc.getDocumentElement().getFirstChild();

        assertEquals("b", b.getLocalName());
        assertEquals("uri-ns1", b.getNamespaceURI());
        assertEquals("uri-ns1", DomUtilities.getNamespaceURI(b, "ns1"));
        assertEquals("uri-ns2", DomUtilities.getNamespaceURI(b, "ns2"));
    }

    @Test
    public void getNamespaceTest3() throws Exception {
        String xml;
        Document doc;
        Element b;
        xml = "<ns1:a xmlns:ns1=\"uri-ns1\"><ns1:b xmlns:ns2=\"uri-ns2\"/></ns1:a>";
        doc = DomUtilities.stringToDom(xml);
        b = (Element) doc.getDocumentElement().getFirstChild();

        assertEquals("b", b.getLocalName());
        assertEquals("uri-ns1", b.getNamespaceURI());
        assertEquals("uri-ns1", DomUtilities.getNamespaceURI(b, "ns1"));
        assertEquals("uri-ns2", DomUtilities.getNamespaceURI(b, "ns2"));
    }

    @Test
    public void getPrefixTest1() throws Exception {
        String xml;
        Document doc;
        Element b;
        xml = "<ns1:a xmlns:ns1=\"uri-ns1\"><ns1:b xmlns:ns2=\"uri-ns2\"/></ns1:a>";
        doc = DomUtilities.stringToDom(xml);
        b = (Element) doc.getDocumentElement().getFirstChild();

        assertEquals("b", b.getLocalName());
        assertEquals("ns1", DomUtilities.getPrefix(b, "uri-ns1"));
        assertEquals("ns2", DomUtilities.getPrefix(b, "uri-ns2"));
    }

    @Test
    public void getPrefixTest2() throws Exception {
        String xml;
        Document doc;
        Element b;
        xml = "<ns1:a xmlns:ns1=\"uri-ns1\" xmlns=\"uri-ns2\"><ns1:b/></ns1:a>";
        doc = DomUtilities.stringToDom(xml);
        b = (Element) doc.getDocumentElement().getFirstChild();

        assertEquals("b", b.getLocalName());

        String thePrefix = DomUtilities.getPrefix(b, "uri-ns2");
        assertNotNull(thePrefix);
        assertEquals("Default namespace not detected", "", thePrefix);
    }

    @Test
    public void getPrefixTest3() throws Exception {
        String xml;
        Document doc;
        Element b;
        xml = "<ns1:a xmlns:ns1=\"uri-ns1\" xmlns=\"uri-ns2\"><ns1:b/></ns1:a>";
        doc = DomUtilities.stringToDom(xml);
        b = (Element) doc.getDocumentElement().getFirstChild();

        assertEquals("b", b.getLocalName());

        String thePrefix = DomUtilities.getPrefix(b, "uri-ns3");
        assertNull(thePrefix);
    }

    @Test
    public void getPrefixTest_SoapSignature() throws Exception {
        String xml;
        Document doc;
        Element signature;
        xml = "<soap:Envelope xmlns:soap='http://www.w3.org/2003/05/soap-envelope'><soap:Header><wsse:Security xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><dsSignedInfo xmlns='http://www.w3.org/2000/09/xmldsig#'/><dsSignatureValue xmlns='http://www.w3.org/2000/09/xmldsig#'/><dsKeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'/></ds:Signature></wsse:Security></soap:Header><soap:Body/></soap:Envelope>";
        doc = DomUtilities.stringToDom(xml);
        signature = DomUtilities.getFirstChildElementByNames(doc.getDocumentElement(), "Header", "Security", "Signature");

        assertEquals("Signature", signature.getLocalName());

        String thePrefix = DomUtilities.getPrefix(signature, "http://www.w3.org/2000/09/xmldsig#");
        assertEquals("ds", thePrefix);

        thePrefix = DomUtilities.getPrefix(signature, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        assertEquals("wsse", thePrefix);

        thePrefix = DomUtilities.getPrefix(signature, "http://www.w3.org/2003/05/soap-envelope");
        assertEquals("soap", thePrefix);

    }
}
