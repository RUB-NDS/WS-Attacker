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

import java.util.*;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.signature.ReferenceElement;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureElement;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureManager;
import wsattacker.plugin.signatureWrapping.util.signature.XPathElement;

public class SignatureManagerTest
{

  private Logger log;

  @BeforeClass
  public static void setUpBeforeClass()
                                       throws Exception
  {
    Logger.getLogger("wsattacker.plugin.signatureWrapping").setLevel(Level.ALL);
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
    log = Logger.getLogger(getClass());
  }

  @After
  public void tearDown()
                        throws Exception
  {
  }

  @Test
  public void referenceTest()
                             throws Exception
  {
    log.info("### Reading Rampart message, 2 Refereneces 0 XPaths");
    SignatureManager manager = new SignatureManager();
    Document doc = DomUtilities.readDocument("src/test/resources/signed_rampart_message.xml");
    manager.setDocument(doc);
    assertEquals(1, manager.getSignatureElements().size());
    SignatureElement sig = manager.getSignatureElements().get(0);
    assertNotNull(sig);
    List<ReferenceElement> refs = sig.getReferences();
    assertEquals(2, refs.size());
    assertEquals("#id-42", refs.get(0).getURI());
    assertEquals("soapenv:Body", refs.get(0).getReferencedElement().getNodeName());
    assertEquals("#Timestamp-40", refs.get(1).getURI());
    assertEquals("wsu:Timestamp", refs.get(1).getReferencedElement().getNodeName());
  }

  @Test
  public void xpathTest()
                         throws Exception
  {
    log.info("### Reading XSpRES message, 1 Reference 2 XPaths");
    SignatureManager manager = new SignatureManager();
    Document doc = DomUtilities.readDocument("src/test/resources/signed_xspres_message.xml");
    manager.setDocument(doc);
    assertEquals(1, manager.getSignatureElements().size());
    SignatureElement sig = manager.getSignatureElements().get(0);
    assertNotNull(sig);
    List<ReferenceElement> refs = sig.getReferences();
    assertEquals(1, refs.size());
    assertTrue(refs.get(0).getURI().isEmpty());
    List<XPathElement> xpaths = refs.get(0).getXPaths();
    assertNotNull(xpaths);
    assertEquals(2, xpaths.size());
    assertEquals("intersect", xpaths.get(0).getFilter());
    assertEquals("/*[local-name()=\"Envelope\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]/*[local-name()=\"Body\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]", xpaths
        .get(0).getExpression());
    assertEquals(1, xpaths.get(0).getReferencedElements().size());
    assertEquals("soapenv:Body", xpaths.get(0).getReferencedElements().get(0).getNodeName());
    assertEquals("union", xpaths.get(1).getFilter());
    assertEquals("/*[local-name()=\"Envelope\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]/*[local-name()=\"Header\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]/*[local-name()=\"Security\" and namespace-uri()=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"][1]/*[local-name()=\"Timestamp\" and namespace-uri()=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"][1]", xpaths
        .get(1).getExpression());
    assertEquals(1, xpaths.get(1).getReferencedElements().size());
    assertEquals("wsu:Timestamp", xpaths.get(1).getReferencedElements().get(0).getNodeName());
  }

    @Test
  public void samlOverSoapTest()
                         throws Exception
  {
    log.info("### Reading XSpRES message, 1 Reference 2 XPaths");
    SignatureManager manager = new SignatureManager();
    Document doc = DomUtilities.readDocument("src/test/resources/saml_over_soap.xml");
    manager.setDocument(doc);
    assertEquals(2, manager.getSignatureElements().size());
    assertEquals(3, manager.getPayloads().size());
    
    Set<String> expectedFastXPaths = new HashSet<String>();
    Set<String> foundFastXPaths = new HashSet<String>();
    
    expectedFastXPaths.add("/soapenv:Envelope[1]/soapenv:Header[1]/wsse:Security[1]/Assertion[1]/ds:Signature[1]/ds:SignedInfo[1]/ds:Reference[1]");
    expectedFastXPaths.add("/soapenv:Envelope[1]/soapenv:Header[1]/wsse:Security[1]/ds:Signature[1]/ds:SignedInfo[1]/ds:Reference[1]");
    expectedFastXPaths.add("/soapenv:Envelope[1]/soapenv:Header[1]/wsse:Security[1]/ds:Signature[1]/ds:SignedInfo[1]/ds:Reference[2]");
    
    for (OptionPayload option : manager.getPayloads()) {
      foundFastXPaths.add(DomUtilities.getFastXPath(option.getReferringElement().getElementNode()));
    }
    assertEquals(expectedFastXPaths, foundFastXPaths);
    
    expectedFastXPaths.clear();
    foundFastXPaths.clear();
    
    expectedFastXPaths.add("/soapenv:Envelope[1]/soapenv:Header[1]/wsse:Security[1]/Assertion[1]");
    expectedFastXPaths.add("/soapenv:Envelope[1]/soapenv:Header[1]/wsse:Security[1]/wsu:Timestamp[1]");
    expectedFastXPaths.add("/soapenv:Envelope[1]/soapenv:Body[1]");
    
    for (OptionPayload option : manager.getPayloads()) {
      Element signedElement = option.getSignedElement();
      assertNotNull("Does not refer anything: "+ option.getReferringElement().getElementNode().getAttribute("URI"), signedElement);
      foundFastXPaths.add(DomUtilities.getFastXPath(signedElement));
    }
    assertEquals(expectedFastXPaths, foundFastXPaths);
    
  }
}
