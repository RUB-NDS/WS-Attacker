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

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.test.util.KeyInfoForTesting;
import wsattacker.plugin.signatureWrapping.test.util.Signer;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.*;

public class SignerTest
{

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
  }

  @After
  public void tearDown()
                        throws Exception
  {
  }

  @Test
  public void testUriDereferencer()
  {
    SoapTestDocument soap = new SoapTestDocument();
    // Add body ID
    Element payloadBody = soap.getDummyPayloadBody();
    String theId = soap.getDummyPayloadBodyWsuId();
    List<Element> referenced = DomUtilities.findElementByWsuId(soap.getDocument(), theId);
    assertEquals(1, referenced.size());
    assertEquals(payloadBody, referenced.get(0));

    // add second wsu:Id element
    Element payloadHeader = soap.getDummyPayloadHeader();
    String otherId = soap.getDummyPayloadHeaderWsuId();
    // find body
    referenced = DomUtilities.findElementByWsuId(soap.getDocument(), theId);
    assertEquals(1, referenced.size());
    assertEquals(payloadBody, referenced.get(0));
    // find header
    referenced = DomUtilities.findElementByWsuId(soap.getDocument(), otherId);
    assertEquals(1, referenced.size());
    assertEquals(payloadHeader, referenced.get(0));

    // bad id
    referenced = DomUtilities.findElementByWsuId(soap.getDocument(), "notcontained");
    assertEquals(0, referenced.size());

  }

  @Test
  public void testUriDereferencerNonDefaultPrefix()
  {
    // Test with other prefix
    SoapTestDocument soap = new SoapTestDocument();
    // Add body ID
    Element payloadBody = soap.getDummyPayloadBody();

    // Add the Id Attribute
    String id = "toSign";
    String prefix = "myprefix";
    Attr a = soap.getDocument().createAttributeNS(URI_NS_WSU, prefix + ":Id");
    a.setValue(id);
    payloadBody.setAttributeNode(a);

    List<Element> referenced = DomUtilities.findElementByWsuId(soap.getDocument(), id);
    assertEquals(1, referenced.size());
    assertEquals(payloadBody, referenced.get(0));
  }

  @Test
  public void testSignerXpath()
                               throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    List<String> toSign = new ArrayList<String>();
    toSign.add("//" + soap.getDummyPayloadBody().getNodeName());
    // Just an Additional Attribute :-)
    Attr a = soap.getDocument().createAttributeNS("http://new", "new:test");
    a.setValue("foo");
    soap.getDummyPayloadBody().setAttributeNode(a);
// System.out.println("ToSign: " +toSign.toString());
// System.out.println(domToString(soap.getDocument()));
    Signer s = new Signer(new KeyInfoForTesting());
    s.sign(soap.getDocument(), toSign);
// System.out.println(domToString(soap.getDocument()));
    assertTrue(s.verifySignature(soap.getDocument()));
  }

  @Test
  public void testSignerId()
                            throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    List<String> toSign = new ArrayList<String>();
    // Declare this as "toSign"
    toSign.add("#" + soap.getDummyPayloadBodyWsuId());
    Signer s = new Signer(new KeyInfoForTesting());
    s.sign(soap.getDocument(), toSign);
    assertTrue(s.verifySignature(soap.getDocument()));
  }

  @Test
  public void testManualSignatureWrapping()
                                           throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    // Original Payload
    soap.getDummyPayloadBody().setTextContent("Original Content");

    List<String> toSign = new ArrayList<String>();
    // Declare this as "toSign"
    toSign.add("#" + soap.getDummyPayloadBodyWsuId());
    Signer s = new Signer(new KeyInfoForTesting());
    s.sign(soap.getDocument(), toSign);

    // Manual Wrapping Attack
    // 1) Move Signature
    Element signed = soap.getDummyPayloadBody();
    signed.getParentNode().removeChild(signed);
    soap.getHeader().appendChild(signed);
    // 2) Add payload
    soap.getDummyPayloadBody().setTextContent("ATTACK PAYLOAD");
    // 3) Add fake id
    soap.getOrCreateAttribute(soap.getDummyPayloadBody(), "Id", PREFIX_NS_WSU, URI_NS_WSU, "newId");
// soap.getDummyPayloadBodyWsuId(); // Same ID as above, not that good

    // Verify Signature
// System.out.println(domToString(soap.getDocument()));
    assertTrue(s.verifySignature(soap.getDocument()));
  }

}
