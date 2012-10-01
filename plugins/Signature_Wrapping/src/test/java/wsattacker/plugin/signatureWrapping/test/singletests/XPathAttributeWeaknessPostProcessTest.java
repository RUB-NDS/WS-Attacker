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
package wsattacker.plugin.signatureWrapping.test.singletests;

import static org.junit.Assert.*;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static wsattacker.plugin.signatureWrapping.xpath.weakness.util.XPathWeaknessTools.isAncestorOf;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.*;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.*;

import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.xpath.parts.AbsoluteLocationPath;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;
import wsattacker.plugin.signatureWrapping.xpath.weakness.XPathAttributeWeaknessPostProcess;

public class XPathAttributeWeaknessPostProcessTest
{
  private static Logger log = Logger.getLogger(XPathAttributeWeaknessPostProcessTest.class);

  @BeforeClass
  public static void setUpBeforeClass()
                                       throws Exception
  {
    Logger.getLogger(XPathAttributeWeaknessPostProcess.class).setLevel(Level.INFO);
    log.setLevel(Level.TRACE);
  }

  @AfterClass
  public static void tearDownAfterClass()
                                         throws Exception
  {
  }

  @Before
  public void setUp()
                     throws Exception
  {
  }

  @After
  public void tearDown()
                        throws Exception
  {
  }

  @Test
  public void isAncestorTest()
  {
    SoapTestDocument soap = new SoapTestDocument();
    soap.getDummyPayloadBody();

    // okay
    assertEquals(1, isAncestorOf(soap.getEnvelope(), soap.getHeader()));
    assertEquals(1, isAncestorOf(soap.getEnvelope(), soap.getBody()));
    assertEquals(2, isAncestorOf(soap.getEnvelope(), soap.getDummyPayloadBody()));

    // wrong -> isDescendantOf
    assertEquals(-1, isAncestorOf(soap.getHeader(), soap.getEnvelope()));
    assertEquals(-1, isAncestorOf(soap.getBody(), soap.getEnvelope()));
    assertEquals(-1, isAncestorOf(soap.getDummyPayloadBody(), soap.getEnvelope()));

    // wrong -> isSelf
    assertEquals(0, isAncestorOf(soap.getHeader(), soap.getHeader()));
  }

  @Test
  public void abuseWeaknessWithNamespaceIdTest()
                                                throws Exception
  {

    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();

    Element signed = soap.getDummyPayloadBody();
    String id = soap.getDummyPayloadBodyWsuId();

    Element payload = (Element) signed.cloneNode(true);

    soap.getHeader().appendChild(payload);

    String xpath = "/soapenv:Envelope//*[@wsu:Id='" + id + "']";
    log.info("Using XPath: " + xpath);
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    Step step = abs.getRelativeLocationPaths().get(2);

    XPathAttributeWeaknessPostProcess aw = new XPathAttributeWeaknessPostProcess(step);

    assertEquals(3, aw.getNumberOfPossibilites());

    Attr sa, pa;

    aw.abuseWeakness(0, signed, payload);
    log.info("abuseWeakness(0, signed, payload)\n" + domToString(doc, true));
    sa = signed.getAttributeNodeNS(URI_NS_WSU, "Id");
    pa = payload.getAttributeNodeNS(URI_NS_WSU, "Id");
    assertNotNull(sa);
    assertNotNull(pa);
    assertEquals(sa.getTextContent(), id);
    assertFalse(pa.getTextContent().isEmpty());
    assertEquals(pa.getTextContent(), "attack" + id);
    assertFalse(sa.getTextContent().equals(pa.getTextContent()));

    aw.abuseWeakness(2, signed, payload);
    log.info("abuseWeakness(2, signed, payload)\n" + domToString(doc, true));
    sa = signed.getAttributeNodeNS(URI_NS_WSU, "Id");
    pa = payload.getAttributeNodeNS(URI_NS_WSU, "Id");
    assertNotNull(sa);
    assertNotNull(pa);
    assertEquals(sa.getTextContent(), id);
    assertFalse(pa.getTextContent().isEmpty());
    assertEquals(sa.getTextContent(), pa.getTextContent());

    aw.abuseWeakness(1, signed, payload);
    log.info("abuseWeakness(1, signed, payload)\n" + domToString(doc, true));
    sa = signed.getAttributeNodeNS(URI_NS_WSU, "Id");
    pa = payload.getAttributeNodeNS(URI_NS_WSU, "Id");
    assertNotNull(sa);
    assertNull(pa);
    assertEquals(sa.getTextContent(), id);
  }

  @Test
  public void abuseWeaknessNoNamespaceIdTest()
                                              throws Exception
  {

    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();

    Element signed = soap.getDummyPayloadBody();
    String id = "signed";
    Attr idAttr = doc.createAttribute("ID");
    idAttr.setTextContent(id);
    signed.setAttributeNode(idAttr);

    Element payload = (Element) signed.cloneNode(true);

    soap.getHeader().appendChild(payload);

    String xpath = "/soapenv:Envelope//*[@ID='" + id + "']";
    log.info("Using XPath: " + xpath);
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    Step step = abs.getRelativeLocationPaths().get(2);

    XPathAttributeWeaknessPostProcess aw = new XPathAttributeWeaknessPostProcess(step);

    assertEquals(3, aw.getNumberOfPossibilites());

    Attr sa, pa;

    aw.abuseWeakness(0, signed, payload);
    log.info("abuseWeakness(0, signed, payload)\n" + domToString(doc, true));
    sa = signed.getAttributeNode("ID");
    pa = payload.getAttributeNode("ID");
    assertNotNull(sa);
    assertNotNull(pa);
    assertEquals(sa.getTextContent(), id);
    assertFalse(pa.getTextContent().isEmpty());
    assertEquals(pa.getTextContent(), "attack" + id);
    assertFalse(sa.getTextContent().equals(pa.getTextContent()));

    aw.abuseWeakness(2, signed, payload);
    log.info("abuseWeakness(2, signed, payload)\n" + domToString(doc, true));
    sa = signed.getAttributeNode("ID");
    pa = payload.getAttributeNode("ID");
    assertNotNull(sa);
    assertNotNull(pa);
    assertEquals(sa.getTextContent(), id);
    assertFalse(pa.getTextContent().isEmpty());
    assertEquals(sa.getTextContent(), pa.getTextContent());

    aw.abuseWeakness(1, signed, payload);
    log.info("abuseWeakness(1, signed, payload)\n" + domToString(doc, true));
    sa = signed.getAttributeNode("ID");
    pa = payload.getAttributeNode("ID");
    assertNotNull(sa);
    assertNull(pa);
    assertEquals(sa.getTextContent(), id);
  }

  @Test
  public void abuseWeaknessIDinPreXPathTest()
                                             throws Exception
  {

    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();

    Element signedIDelement = soap.getDummyPayloadBody();
    Element signed = doc.createElementNS("http://test", "test:subelement");
    signedIDelement.appendChild(signed);

    String id = "signed";
    Attr idAttr = doc.createAttribute("ID");
    idAttr.setTextContent(id);
    signedIDelement.setAttributeNode(idAttr);

    Element payloadIDelement = (Element) signedIDelement.cloneNode(true);
    Element payload = DomUtilities.getAllChildElements(payloadIDelement).get(0); // there is only one :-)

    soap.getHeader().appendChild(payloadIDelement);

    String xpath = "/soapenv:Envelope//*[@ID='" + id + "']/test:subelement";
    log.info("Using XPath: " + xpath);
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    Step step = abs.getRelativeLocationPaths().get(2);

    XPathAttributeWeaknessPostProcess aw = new XPathAttributeWeaknessPostProcess(step);

    assertEquals(3, aw.getNumberOfPossibilites());

    Attr sa, pa;

    aw.abuseWeakness(0, signed, payload);
    log.info("abuseWeakness(0, signed, payload)\n" + domToString(doc, true));
    sa = signedIDelement.getAttributeNode("ID");
    pa = payloadIDelement.getAttributeNode("ID");
    assertNotNull(sa);
    assertNotNull(pa);
    assertEquals(sa.getTextContent(), id);
    assertFalse(pa.getTextContent().isEmpty());
    assertEquals(pa.getTextContent(), "attack" + id);
    assertFalse(sa.getTextContent().equals(pa.getTextContent()));

    aw.abuseWeakness(2, signed, payload);
    log.info("abuseWeakness(2, signed, payload)\n" + domToString(doc, true));
    sa = signedIDelement.getAttributeNode("ID");
    pa = payloadIDelement.getAttributeNode("ID");
    assertNotNull(sa);
    assertNotNull(pa);
    assertEquals(sa.getTextContent(), id);
    assertFalse(pa.getTextContent().isEmpty());
    assertEquals(sa.getTextContent(), pa.getTextContent());

    aw.abuseWeakness(1, signed, payload);
    log.info("abuseWeakness(1, signed, payload)\n" + domToString(doc, true));
    sa = signedIDelement.getAttributeNode("ID");
    pa = payloadIDelement.getAttributeNode("ID");
    assertNotNull(sa);
    assertNull(pa);
    assertEquals(sa.getTextContent(), id);
  }

}
