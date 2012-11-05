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
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.*;

import java.util.List;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.schema.NullSchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants;
import wsattacker.plugin.signatureWrapping.util.signature.ReferringElementInterface;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureManager;
import wsattacker.plugin.signatureWrapping.xpath.parts.AbsoluteLocationPath;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;
import wsattacker.plugin.signatureWrapping.xpath.weakness.XPathDescendantWeakness;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.XPathWeaknessTools;
import wsattacker.plugin.signatureWrapping.xpath.wrapping.WrappingOracle;

public class XPathDescendantWeaknessTest
{

  private static Logger log = Logger.getLogger(XPathDescendantWeaknessTest.class);

  private static void logClass(Level level)
  {

    Logger.getLogger(XPathDescendantWeakness.class).setLevel(level);
  }

  private static void logTestClass(Level level)
  {
    log.setLevel(level);
  }

  private static void log(Level level)
  {
    logTestClass(level);
    logClass(level);
  }

  @BeforeClass
  public static void setUpBeforeClass()
                                       throws Exception
  {
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
    log(Level.OFF);
  }

  @After
  public void tearDown()
                        throws Exception
  {
  }

  @Test
  public void detectHashedPostTreeTest1()
                                         throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    String postXPath = "ns1:payloadBody";

    Element signedElement = soap.getDummyPayloadBody();
    signedElement.setTextContent("Original Content");

    Element hashed = XPathWeaknessTools.detectHashedPostTree(signedElement, postXPath);
    assertNotNull(hashed);
    assertEquals(soap.getDummyPayloadBody(), hashed);
  }

  @Test
  public void detectHashedPostTreeTest2()
                                         throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();
    String postXPath = "ns1:payloadBody";

    Element signedElement = soap.getDummyPayloadBody();
    signedElement.appendChild(doc.createElementNS("http://ns2", "ns2:a"));
    Element theSigned = doc.createElementNS("http://ns2", "ns2:b");
    signedElement.appendChild(theSigned);
    signedElement.appendChild(doc.createElementNS("http://ns2", "ns2:c"));
    signedElement = theSigned;

    signedElement.setTextContent("Original Content");

    Element hashed = XPathWeaknessTools.detectHashedPostTree(signedElement, postXPath);
    assertNotNull(hashed);
    assertEquals(soap.getDummyPayloadBody(), hashed);
  }

  @Test
  public void createPayloadPostPartTest0()
                                          throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();

    SchemaAnalyzerInterface sa = new SchemaAnalyzer();
    sa.appendSchema(DomUtilities.readDocument("src/main/resources/XML Schema/soap11.xsd"));
    String postXPath = "ns1:payloadBody";

    Element bodyChild = soap.getDummyPayloadBody();

    Element signedElement = bodyChild;
    signedElement.setTextContent("Original Content");

    // create payload element
    Element payloadElement = doc.createElementNS("http://attacker.org", "atk:XYZ");
    payloadElement.setTextContent("ATTACK");

    Element signedPostPart = XPathWeaknessTools.detectHashedPostTree(signedElement, postXPath);

    Element payloadPostPart = XPathWeaknessTools
        .createPayloadPostPart(signedPostPart, signedElement, payloadElement);
    assertNotNull(payloadPostPart);

    assertEquals(payloadPostPart.getNodeName(), payloadElement.getNodeName());

    List<Element> children = DomUtilities.getAllChildElements(payloadPostPart);
    assertEquals(children.size(), DomUtilities.getAllChildElements(bodyChild).size());

    assertNotNull(signedPostPart);
    assertEquals(signedPostPart, soap.getDummyPayloadBody());

    signedPostPart.getParentNode().replaceChild(payloadPostPart, signedPostPart);

    assertEquals("/soapenv:Envelope[1]/soapenv:Body[1]/atk:XYZ[1]", DomUtilities.getFastXPath(payloadElement));
  }

  @Test
  public void createPayloadPostPartTest1()
                                          throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();

    SchemaAnalyzerInterface sa = new SchemaAnalyzer();
    sa.appendSchema(DomUtilities.readDocument("src/main/resources/XML Schema/soap11.xsd"));
    String postXPath = "ns1:payloadBody/ns2:b";

    Element bodyChild = soap.getDummyPayloadBody();
    Element a = doc.createElementNS("http://ns2", "ns2:a");
    Element b = doc.createElementNS("http://ns2", "ns2:b");
    Element c = doc.createElementNS("http://ns2", "ns2:c");
    bodyChild.appendChild(a);
    bodyChild.appendChild(b);
    bodyChild.appendChild(c);

    Element signedElement = b;
    signedElement.setTextContent("Original Content");

    // create payload element
    Element payloadElement = doc.createElementNS("http://attacker.org", "atk:XYZ");
    payloadElement.setTextContent("ATTACK");

    Element signedPostPart = XPathWeaknessTools.detectHashedPostTree(signedElement, postXPath);

    Element payloadPostPart = XPathWeaknessTools
        .createPayloadPostPart(signedPostPart, signedElement, payloadElement);
    assertNotNull(payloadPostPart);

    assertEquals(signedPostPart.getNodeName(), payloadPostPart.getNodeName());

    List<Element> children = DomUtilities.getAllChildElements(payloadPostPart);
    assertEquals(children.size(), DomUtilities.getAllChildElements(bodyChild).size());

    assertEquals(children.get(0).getNodeName(), a.getNodeName());
    assertEquals(children.get(1).getNodeName(), payloadElement.getNodeName());
    assertEquals(children.get(2).getNodeName(), c.getNodeName());

    assertNotNull(signedPostPart);
    assertEquals(signedPostPart, soap.getDummyPayloadBody());

    signedPostPart.getParentNode().replaceChild(payloadPostPart, signedPostPart);

    assertEquals("/soapenv:Envelope[1]/soapenv:Body[1]/ns1:payloadBody[1]/atk:XYZ[1]", DomUtilities.getFastXPath(payloadElement));
  }

  @Test
  public void createPayloadPostPartTest2()
                                          throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();

    SchemaAnalyzerInterface sa = new SchemaAnalyzer();
    sa.appendSchema(DomUtilities.readDocument("src/main/resources/XML Schema/soap11.xsd"));
    String postXPath = "soapenv:Envelope/soapenv:Body/ns1:payloadBody/ns2:b";

    Element bodyChild = soap.getDummyPayloadBody();
    Element a = doc.createElementNS("http://ns2", "ns2:a");
    Element b = doc.createElementNS("http://ns2", "ns2:b");
    Element c = doc.createElementNS("http://ns2", "ns2:c");
    bodyChild.appendChild(a);
    bodyChild.appendChild(b);
    bodyChild.appendChild(c);

    Element signedElement = b;
    signedElement.setTextContent("Original Content");

    // create payload element
    Element payloadElement = doc.createElementNS("http://attacker.org", "atk:XYZ");
    payloadElement.setTextContent("ATTACK");

    Element signedPostPart = XPathWeaknessTools.detectHashedPostTree(signedElement, postXPath);

    Element payloadPostPart = XPathWeaknessTools
        .createPayloadPostPart(signedPostPart, signedElement, payloadElement);
    assertNotNull(payloadPostPart);

    assertEquals(signedPostPart.getNodeName(), soap.getEnvelope().getNodeName());

    assertNotNull(signedPostPart);
    assertEquals(signedPostPart, soap.getEnvelope());
    assertEquals(payloadPostPart.getNodeName(), soap.getEnvelope().getNodeName());

    signedPostPart.getParentNode().replaceChild(payloadPostPart, signedPostPart);

    assertEquals("/soapenv:Envelope[1]/soapenv:Body[1]/ns1:payloadBody[1]/atk:XYZ[1]", DomUtilities.getFastXPath(payloadElement));
  }

  @Test
  public void simpleXpathDescendatntWeaknessTest()
                                                  throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();

    SchemaAnalyzerInterface sa = new SchemaAnalyzer();
    sa.appendSchema(DomUtilities.readDocument("src/main/resources/XML Schema/soap11.xsd"));
    String xpath = "/soapenv:Envelope//ns1:payloadBody/ns2:b";

    Document doc = soap.getDocument();
    // get signed element
    Element signedElement = soap.getDummyPayloadBody();
    signedElement.appendChild(doc.createElementNS("http://ns2", "ns2:a"));
    Element theSigned = doc.createElementNS("http://ns2", "ns2:b");
    signedElement.appendChild(theSigned);
    signedElement.appendChild(doc.createElementNS("http://ns2", "ns2:c"));
    signedElement = theSigned;

    signedElement.setTextContent("Original Content");
// String fastXPathSignedPre = DomUtilities.getFastXPath(signedElement);

    // create payload element
// Element payloadElement = doc.createElementNS("http://attacker.org", "atk:XYZ");
    Element payloadElement = doc.createElementNS("http://ns2", "ns2:b");
// NamespaceConstants.PREFIX_NS_WSATTACKER+"payloadBody");
    payloadElement.setTextContent("ATTACK");

    // 1) Build the XPathDescendantWeakness
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    XPathDescendantWeakness xpw = new XPathDescendantWeakness(abs.getRelativeLocationPaths().get(1), doc, payloadElement, sa);

    assertEquals("/soapenv:Envelope", xpw.getPreXPath());
    assertEquals("ns1:payloadBody/ns2:b", xpw.getPostXPath());
    assertEquals(2 * 3 + 2 * 1 + 2 * 2, xpw.getNumberOfPossibilities()); // 3 in env, 1 in header, 2 in body

    // 2) Abuse the Weakness
    for (int i = 0; i < xpw.getNumberOfPossibilities(); ++i)
    {
      Document copyDoc = DomUtilities.createNewDomFromNode(doc.getDocumentElement());
      Element copySigned = DomUtilities.findCorrespondingElement(copyDoc, signedElement);
      Element copyPayload = (Element) copyDoc.importNode(payloadElement.cloneNode(true), true);

      xpw.abuseWeakness(i, copySigned, copyPayload);
      log.trace("### " + i + ")\n" + domToString(copyDoc, true) + "\n");

      assertNotNull(copySigned);
      assertNotNull(copyPayload);
      String fastXPathSignedPost = DomUtilities.getFastXPath(copySigned);
      assertTrue(!fastXPathSignedPost.isEmpty());
      String fastXPathPayloadPost = DomUtilities.getFastXPath(copyPayload);
      assertTrue(!fastXPathPayloadPost.isEmpty());

      List<Element> matched = (List<Element>) DomUtilities.evaluateXPath(copyDoc, xpath);
      assertEquals(2, matched.size());

      if (matched.get(0) == copySigned)
      {
        assertEquals(matched.get(0), copySigned);
        assertEquals(matched.get(1), copyPayload);
      }
      else
      {
        assertEquals(matched.get(0), copyPayload);
        assertEquals(matched.get(1), copySigned);
      }
    }
  }

  @Test
  public void xpathDescendantWeaknessMinimalPostXPathTest()
                                                           throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();

    SchemaAnalyzerInterface sa = new SchemaAnalyzer();
    sa.appendSchema(DomUtilities.readDocument("src/main/resources/XML Schema/soap11.xsd"));
    String xpath = "//ns1:payloadBody";

    Document doc = soap.getDocument();
    // get signed element
    Element signedElement = soap.getDummyPayloadBody();

    signedElement.setTextContent("Original Content");
// String fastXPathSignedPre = DomUtilities.getFastXPath(signedElement);

    // create payload element
    Element payloadElement = (Element) signedElement.cloneNode(true);
    payloadElement.setTextContent("ATTACK");

    // 1) Build the XPathDescendantWeakness
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    XPathDescendantWeakness xpw = new XPathDescendantWeakness(abs.getRelativeLocationPaths().get(0), doc, payloadElement, sa);

    assertEquals("", xpw.getPreXPath());
    assertEquals("ns1:payloadBody", xpw.getPostXPath());
    assertEquals(2 * 3 + 2 * 1 + 2 * 2, xpw.getNumberOfPossibilities()); // 3 in env, 1 in header, 2 in body

    // 2) Abuse the Weakness
    for (int i = 0; i < xpw.getNumberOfPossibilities(); ++i)
    {
      WeaknessLog.clean();
      Document copyDoc = DomUtilities.createNewDomFromNode(doc.getDocumentElement());
      Element copySigned = DomUtilities.findCorrespondingElement(copyDoc, signedElement);
      Element copyPayload = (Element) copyDoc.importNode(payloadElement.cloneNode(true), true);

      xpw.abuseWeakness(i, copySigned, copyPayload);
      log.trace("### " + i + ")\n" + domToString(copyDoc, true) + "\n");

      assertNotNull(copySigned);
      assertNotNull(copyPayload);
      String fastXPathSignedPost = DomUtilities.getFastXPath(copySigned);
      assertTrue(!fastXPathSignedPost.isEmpty());
      String fastXPathPayloadPost = DomUtilities.getFastXPath(copyPayload);
      assertTrue(!fastXPathPayloadPost.isEmpty());

      List<Element> matched = (List<Element>) DomUtilities.evaluateXPath(copyDoc, xpath);
      assertEquals(String.format("\ni=%d\nXPath: %s\nDoc:\n%s\nLog:\n%s", i, xpath, DomUtilities.showOnlyImportant(copyDoc), WeaknessLog.representation()), 2, matched.size());

      if (matched.get(0) == copySigned)
      {
        assertEquals(matched.get(0), copySigned);
        assertEquals(matched.get(1), copyPayload);
      }
      else
      {
        assertEquals(matched.get(0), copyPayload);
        assertEquals(matched.get(1), copySigned);
      }
    }
  }

  @Test
  public void xpathDescendantWithAttributeWeaknessTest()
                                                        throws Exception
  {
// log(Level.ALL);
    log.info("Starting xpathDescendantWithAttributeWeaknessTest");

    String[] xpatharray =
    { "/soapenv:Envelope//ns1:payloadBody[@wsu:Id='%s']/ns2:b", "//*[@wsu:Id='%s']/ns2:b" };

    for (String xpathformat : xpatharray)
    {
      SoapTestDocument soap = new SoapTestDocument();

      SchemaAnalyzerInterface sa = new SchemaAnalyzer();

      Document doc = soap.getDocument();
      // get signed element
      Element signedElement = soap.getDummyPayloadBody();
      signedElement.appendChild(doc.createElementNS("http://ns2", "ns2:a"));
      Element theSigned = doc.createElementNS("http://ns2", "ns2:b");
      signedElement.appendChild(theSigned);
      signedElement.appendChild(doc.createElementNS("http://ns2", "ns2:c"));
      signedElement = theSigned;

      sa.appendSchema(DomUtilities.readDocument("src/main/resources/XML Schema/soap11.xsd"));
      String id = soap.getDummyPayloadBodyWsuId();
      String xpath = String.format(xpathformat, id);

      signedElement.setTextContent("Original Content");
// String fastXPathSignedPre = DomUtilities.getFastXPath(signedElement);

      // create payload element
// Element payloadElement = doc.createElementNS("http://attacker.org", "atk:XYZ");
      Element payloadElement = doc.createElementNS("http://ns2", "ns2:b");
// NamespaceConstants.PREFIX_NS_WSATTACKER+"payloadBody");
      payloadElement.setTextContent("ATTACK");

      // 1) Build the XPathDescendantWeakness
      AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
      Step descendantStep = abs.getRelativeLocationPaths().get(0);
      while (!descendantStep.getAxisSpecifier().getAxisName().getAxisName().startsWith("descendant"))
        descendantStep = descendantStep.getNextStep();
      XPathDescendantWeakness xpw = new XPathDescendantWeakness(descendantStep, doc, payloadElement, sa);

      assertEquals((2 * 3 + 2 * 1 + 2 * 2) * 3, xpw.getNumberOfPossibilities()); // (3 in env, 1 in header, 2 in body) *
// 3
// for ID

      // 2) Abuse the Weakness
      for (int i = 0; i < xpw.getNumberOfPossibilities(); ++i)
      {
        Document copyDoc = DomUtilities.createNewDomFromNode(doc.getDocumentElement());
        Element copySigned = DomUtilities.findCorrespondingElement(copyDoc, signedElement);
        Element copyPayload = (Element) copyDoc.importNode(payloadElement.cloneNode(true), true);

        log.trace("### Abuse Weakness " + i);
        xpw.abuseWeakness(i, copySigned, copyPayload);
        log.trace("\n" + domToString(copyDoc, true) + "\n");

        assertNotNull(copySigned);
        assertNotNull(copyPayload);
        String fastXPathSignedPost = DomUtilities.getFastXPath(copySigned);
        assertTrue(!fastXPathSignedPost.isEmpty());
        String fastXPathPayloadPost = DomUtilities.getFastXPath(copyPayload);
        assertTrue(!fastXPathPayloadPost.isEmpty());

        List<Element> matched = (List<Element>) DomUtilities.evaluateXPath(copyDoc, xpath);

        if (matched.size() == 1)
        {
          assertEquals(matched.get(0), copySigned);
          log.trace("Good try, only one Element matched!");
          continue;
        }
        else if (matched.size() == 2)
        {

          if (matched.get(0) == copySigned)
          {
            assertEquals(domToString(matched.get(0), true) + "!=\n" + domToString(copySigned, true), matched.get(0), copySigned);
            assertEquals(domToString(matched.get(1), true) + "!=\n" + domToString(copyPayload, true), matched.get(1), copyPayload);
          }
          else
          {
            assertEquals(domToString(matched.get(0), true) + "!=\n" + domToString(copyPayload, true), matched.get(0), copyPayload);
            assertEquals(domToString(matched.get(1), true) + "!=\n" + domToString(copySigned, true), matched.get(1), copySigned);
          }
          continue;
        }
        fail(String.format("Matched '%d' Elements and not 1 or 2 Elements. FAIL", matched.size()));
      }
    }
  }

  @Test
  public void xpathDescendantWeaknessReferenceIdEquivalentTest()
                                                                throws Exception
  {
    log(Level.ALL);
    SoapTestDocument soap = new SoapTestDocument();

    SchemaAnalyzerInterface sa = new SchemaAnalyzer();
    sa.appendSchema(DomUtilities.readDocument("src/main/resources/XML Schema/soap11.xsd"));
    // get signed element
    Element signedElement = soap.getDummyPayloadBody();
    String id = soap.getDummyPayloadBodyWsuId();
    String xpath = String.format("//*[@wsu:Id='%s']", id);

    Document doc = soap.getDocument();

    signedElement.setTextContent("Original Content");
// String fastXPathSignedPre = DomUtilities.getFastXPath(signedElement);

    // create payload element
    Element payloadElement = doc
        .createElementNS(NamespaceConstants.URI_NS_WSATTACKER, NamespaceConstants.PREFIX_NS_WSATTACKER + ":payloadBody");
    payloadElement.setTextContent("ATTACK");

    // 1) Build the XPathDescendantWeakness
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    XPathDescendantWeakness xpw = new XPathDescendantWeakness(abs.getRelativeLocationPaths().get(0), doc, payloadElement, sa);

    assertEquals((2 * 3 + 2 * 1 + 2 * 2) * 3, xpw.getNumberOfPossibilities()); // (3 in env, 1 in header, 2 in body)*3
// for attr

    // 2) Abuse the Weakness
    for (int i = 0; i < xpw.getNumberOfPossibilities(); ++i)
    {
      Document copyDoc = DomUtilities.createNewDomFromNode(doc.getDocumentElement());
      Element copySigned = DomUtilities.findCorrespondingElement(copyDoc, signedElement);
      Element copyPayload = (Element) copyDoc.importNode(payloadElement.cloneNode(true), true);

      xpw.abuseWeakness(i, copySigned, copyPayload);
      log.trace("### " + i + ")\n" + domToString(copyDoc, true) + "\n");

      assertNotNull(copySigned);
      assertNotNull(copyPayload);
      String fastXPathSignedPost = DomUtilities.getFastXPath(copySigned);
      assertTrue(!fastXPathSignedPost.isEmpty());
      String fastXPathPayloadPost = DomUtilities.getFastXPath(copyPayload);
      assertTrue(!fastXPathPayloadPost.isEmpty());

      List<Element> matched = (List<Element>) DomUtilities.evaluateXPath(copyDoc, xpath);

      if (matched.size() == 1)
      {
        assertEquals(matched.get(0), copySigned);
        log.trace("Good try, only one Element matched!");
        continue;
      }
      else if (matched.size() == 2)
      {

        if (matched.get(0) == copySigned)
        {
          assertEquals(domToString(matched.get(0), true) + "!=\n" + domToString(copySigned, true), matched.get(0), copySigned);
          assertEquals(domToString(matched.get(1), true) + "!=\n" + domToString(copyPayload, true), matched.get(1), copyPayload);
        }
        else
        {
          assertEquals(domToString(matched.get(0), true) + "!=\n" + domToString(copyPayload, true), matched.get(0), copyPayload);
          assertEquals(domToString(matched.get(1), true) + "!=\n" + domToString(copySigned, true), matched.get(1), copySigned);
        }
        continue;
      }
      fail(String.format("Matched '%d' Elements and not 1 or 2 Elements. FAIL", matched.size()));
    }
  }

  @Test
  public void withPreXPath() throws Exception
  {
    Document doc = DomUtilities.readDocument("src/test/resources/signed_rampart_message_soap_1.2.xml");
    SchemaAnalyzerInterface sa = new NullSchemaAnalyzer();
    SignatureManager sm = new SignatureManager();
    sm.setDocument(doc);
    OptionPayload option = sm.getPayloads().get(1);
    ReferringElementInterface ref = option.getReferringElement();
    ref.setXPath("/soap:Envelope/soap:Header/wsse:Security"+ref.getXPath());
    AbsoluteLocationPath abs = new AbsoluteLocationPath(ref.getXPath());
    System.out.println(ref.getXPath());
    XPathDescendantWeakness weakness = new XPathDescendantWeakness(abs.getRelativeLocationPaths().get(3), doc, option.getPayloadElement(), sa);
    assertTrue(weakness.getNumberOfPossibilities() > 0);
//    System.out.println(weakness.getNumberOfPossibilities());


    option = sm.getPayloads().get(0);
    option.parseValue(option.getValueAsString().replace("Know-How", "ATTACKER"));
    ref = option.getReferringElement();
    ref.setXPath("/soap:Envelope"+ref.getXPath());
    abs = new AbsoluteLocationPath(ref.getXPath());
    weakness = new XPathDescendantWeakness(abs.getRelativeLocationPaths().get(1), doc, option.getPayloadElement(), sa);
    assertTrue(weakness.getNumberOfPossibilities() > 0);

    WrappingOracle wrap = new WrappingOracle(doc, sm.getPayloads(), sa);
    assertTrue(wrap.maxPossibilities() > 0);
  }
}
