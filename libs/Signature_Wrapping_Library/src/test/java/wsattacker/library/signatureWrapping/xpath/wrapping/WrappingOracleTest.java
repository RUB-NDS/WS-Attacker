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
package wsattacker.library.signatureWrapping.xpath.wrapping;

import java.io.*;
import java.util.*;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.schema.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.library.signatureWrapping.util.KeyInfoForTesting;
import wsattacker.library.signatureWrapping.util.Signer;
import wsattacker.library.signatureWrapping.util.SoapTestDocument;
import wsattacker.library.signatureWrapping.util.dom.DomUtilities;
import static wsattacker.library.signatureWrapping.util.dom.DomUtilities.domToString;
import wsattacker.library.signatureWrapping.util.signature.NamespaceConstants;
import wsattacker.library.signatureWrapping.util.signature.ReferenceElement;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;

public class WrappingOracleTest {

    public static SchemaAnalyzerInterface schemaAnalyser;
    public static Logger log;

    @BeforeClass
    public static void setUpBeforeClass()
      throws Exception {
        schemaAnalyser = new SchemaAnalyzer();
        // Logger
        log = Logger.getLogger(WrappingOracle.class);
        Logger.getLogger("wsattacker.plugin.signaturewrapping.util.signature").setLevel(Level.WARN);
        Logger.getLogger("wsattacker.plugin.signaturewrapping.test.util").setLevel(Level.WARN);
        Logger.getLogger(DomUtilities.class).setLevel(Level.WARN);
        Logger.getLogger(WrappingOracle.class).setLevel(Level.WARN);
// Logger.getLogger("wsattacker.plugin.signaturewrapping.util.wrapping").setLevel(Level.TRACE);

// log.setLevel(Level.ALL);
        Logger.getLogger("wsattacker.plugin.signatureWrapping.schema.SchemaAnalyser").setLevel(Level.ALL);

        // Load Schema Files
        schemaAnalyser = SchemaAnalyzerFactory.getInstance(SchemaAnalyzerFactory.WEBSERVICE);
    }

    @AfterClass
    public static void tearDownAfterClass()
      throws Exception {
    }

    @Before
    public void setUp()
      throws Exception {
        log.setLevel(Level.OFF);
    }

    @After
    public void tearDown()
      throws Exception {
    }

    @Test
    public void testAutomaticReferencedBasedSignatureWrapping11()
      throws Exception {
        log.info("### SOAP 1.1 TEST ###");
        SoapTestDocument soap;
        soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_1);
        testAutomaticReferencedBasedSignatureWrapping(soap);

    }

    @Test
    public void testAutomaticReferencedBasedSignatureWrapping12()
      throws Exception {
        log.info("### SOAP 1.2 TEST ###");
        SoapTestDocument soap;
        soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_2);
        testAutomaticReferencedBasedSignatureWrapping(soap);

    }

    public void testAutomaticReferencedBasedSignatureWrapping(SoapTestDocument soap)
      throws Exception {

        // Original Payload
        String originalContent = "Original Content";
        String payloadContent = "ATTACK CONTENT";
        soap.getDummyPayloadBody().setTextContent(originalContent);

        List<String> toSign = new ArrayList<String>();
        // Declare this as "toSign"
        toSign.add("#" + soap.getDummyPayloadBodyWsuId());
        Signer s = new Signer(new KeyInfoForTesting());
        s.sign(soap.getDocument(), toSign);
        String cmpDocument = domToString(soap.getDocument());
// System.out.println(domToString(soap.getDocument()));

        SignatureManager signatureManager = new SignatureManager();
        signatureManager.setDocument(soap.getDocument());

        List<Payload> payloads = signatureManager.getPayloads();
        assertNotNull(payloads);
        assertEquals(1, payloads.size());
        Payload optionPayload = payloads.get(0);
        assertTrue(optionPayload.getReferringElement() instanceof ReferenceElement);
        assertEquals(toSign.get(0), ((ReferenceElement) optionPayload.getReferringElement()).getURI());

        String thePayload = domToString(soap.getDummyPayloadBody()).replace(originalContent, payloadContent);
        assertTrue(optionPayload.isValid(thePayload));
        optionPayload.setValue(thePayload);

        WrappingOracle wrappingOracle = new WrappingOracle(soap.getDocument(), signatureManager.getPayloads(), schemaAnalyser);

        int max = wrappingOracle.maxPossibilities();
        assertTrue(max > 0);
        Document attackDocument;
        for (int i = 0; i < max; ++i) {
            attackDocument = wrappingOracle.getPossibility(i);
            assertEquals(cmpDocument, domToString(soap.getDocument())); // the original Document must not be
            // Verify Signature
            String attackDocumentAsString = domToString(attackDocument);
            assertTrue("Invalid Message:\n" + domToString(attackDocument), attackDocumentAsString.contains(originalContent));
            assertTrue("Invalid Message:\n" + domToString(attackDocument), attackDocumentAsString.contains(payloadContent));
// System.out.println(attackDocumentAsString);
            if (log.isDebugEnabled()) {
                log.info("FINAL MESSAGE:\n\n" + domToString(attackDocument, true) + "\n\n");
                log.info("Now Validating");
            }
            boolean valid = s.verifySignature(attackDocument);
            if (valid) {
                log.warn("\n#########################################################################\nSignature valid for i=" + i + "\n" + attackDocumentAsString);
                return;
            }
// changed
        }
        fail("Could not find any wrapping attack. None of the " + wrappingOracle.maxPossibilities() + " worked.");
    }

    @Test
    public void testAutomaticXPathBasedSignatureWrapping()
      throws Exception {

        SoapTestDocument soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_2);

        String originalContent = "Original Content";
        String payloadContent = "ATTACK CONTENT";
        soap.getDummyPayloadBody().setTextContent(originalContent);

        List<String> toSign = new ArrayList<String>();
        // Declare this as "toSign"
        toSign.add("//ns1:payloadBody[1]");
        Signer s = new Signer(new KeyInfoForTesting());
        s.sign(soap.getDocument(), toSign);

        SignatureManager signatureManager = new SignatureManager();
        signatureManager.setDocument(soap.getDocument());

        List<Payload> payloads = signatureManager.getPayloads();
        Payload optionPayload = payloads.get(0);

        String thePayload = domToString(soap.getDummyPayloadBody()).replace(originalContent, payloadContent);
        assertTrue(optionPayload.isValid(thePayload));
        optionPayload.setValue(thePayload);

        assertEquals(toSign.size(), payloads.size());

        doGenericSignatureWrapping(soap, signatureManager, s);
    }

    @Test
    public void testAutomaticMultipleXPathBasedSignatureWrapping()
      throws Exception {

        SoapTestDocument soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_2);

        String originalContent = "Original Content";
        String payloadContent = "ATTACK CONTENT";
        soap.getDummyPayloadBody().setTextContent(originalContent + " Body");
        soap.getDummyPayloadHeader().setTextContent(originalContent + " Header");

        List<String> toSign = new ArrayList<String>();
        // Declare this as "toSign"
        toSign.add("//ns1:payloadBody[1]");
        toSign.add("/soap:Envelope//ns1:payloadHeader[1]");
        Signer s = new Signer(new KeyInfoForTesting());
        s.sign(soap.getDocument(), toSign);

        SignatureManager signatureManager = new SignatureManager();
        signatureManager.setDocument(soap.getDocument());

        List<Payload> payloads = signatureManager.getPayloads();
        for (Payload optionPayload : payloads) {
            String thePayload = domToString(optionPayload.getSignedElement()).replace(originalContent, payloadContent);
            assertTrue(optionPayload.isValid(thePayload));
            optionPayload.setValue(thePayload);
        }

        assertEquals(toSign.size(), payloads.size());

        doGenericSignatureWrapping(soap, signatureManager, s);
    }

//	@Test
    public void specialTest() throws Exception {
        SignatureManager signatureManager = new SignatureManager();
        Document doc = DomUtilities.readDocument("src/test/resources/signed_rampart_message_soap_1.2.xml");
        signatureManager.setDocument(doc);
        Payload bodyPayload = signatureManager.getPayloads().get(0);
        bodyPayload.setValue(bodyPayload.getValue().replace("ORIGINAL", "ATTACKER"));
        WrappingOracle wrappingOracle = new WrappingOracle(doc, signatureManager.getPayloads(), schemaAnalyser);
//    Document attackDocument = wrappingOracle.getPossibility(67);
        for (int i = 0; i < wrappingOracle.maxPossibilities(); ++i) {
            System.out.println(i + "/" + wrappingOracle.maxPossibilities());
            wrappingOracle.getPossibility(i);
        }
    }

    @Test
    public void testFeaturedSignatureWrapping()
      throws Exception {

        SoapTestDocument soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_2);

        String originalContent = "Original Content";
        String payloadContent = "ATTACK CONTENT";
        Element firstBodyChild = soap.getDummyPayloadBody();
        Element signed = soap.getDocument().createElementNS(firstBodyChild.getNamespaceURI(), firstBodyChild.getPrefix() + ":signedElement");
        firstBodyChild.appendChild(signed);
        signed.setTextContent(originalContent);
        // create an expired timestamp
        soap.setTimestamp(true, true);

        List<String> toSign = new ArrayList<String>();
        // Declare this as "toSign"
        toSign.add("//wsu:Timestamp[1]");
        toSign.add("//" + firstBodyChild.getNodeName() + "[@wsu:Id='" + soap.getDummyPayloadBodyWsuId() + "']/" + signed.getNodeName() + "[1]");
        Signer s = new Signer(new KeyInfoForTesting());
//    System.out.println(soap);
        s.sign(soap.getDocument(), toSign);
        System.out.println(soap);

        SignatureManager signatureManager = new SignatureManager();
        signatureManager.setDocument(soap.getDocument());

        List<Payload> payloads = signatureManager.getPayloads();
        Payload optionPayload = payloads.get(1);

        String thePayload = domToString(signed).replace(originalContent, payloadContent);
        assertTrue(optionPayload.isValid(thePayload));
        optionPayload.setValue(thePayload);

        assertEquals(toSign.size(), payloads.size());

        doGenericSignatureWrapping(soap, signatureManager, s, true);
    }

    @Test
    public void samlOverSoapTest()
      throws Exception {
        log.info("### Reading SAML over SOAP message");
        SignatureManager manager = new SignatureManager();
        Document doc = DomUtilities.readDocument("src/test/resources/saml_over_soap.xml");
        manager.setDocument(doc);
        assertEquals(2, manager.getSignatureElements().size());
        assertEquals(3, manager.getPayloads().size());

        for (Payload optionPayload : manager.getPayloads()) {
            Element signed = optionPayload.getSignedElement();

            String name = signed.getLocalName();
            if (name.equals("Body")) {
                String thePayload = domToString(signed).replace("Hello world1", "ATTACKER");
                assertTrue(optionPayload.isValid(thePayload));
                optionPayload.setValue(thePayload);
            }
        }
//    Signer s = new Signer(new KeyInfoForTesting());
        // TODO: Write a test which verifies the signature
//	doGenericSignatureWrapping(doc, manager, s);
        WrappingOracle wrappingOracle = new WrappingOracle(doc, manager.getPayloads(), schemaAnalyser);
        wrappingOracle.getPossibility(521);
//	Document attackDocument;
//	int max = wrappingOracle.maxPossibilities();
//	int lastPrint = 0;
//	java.util.Date lastDate, newDate;
//	lastDate = new java.util.Date();
//	System.out.println("  0% " + lastDate);
//    for (int i = 0; i < max; ++i) {
//	  int thisPrint = 100*i/max;
//	  if (thisPrint > lastPrint) {
//		  newDate = new java.util.Date();
//		  System.out.format("%3d%% %s // + %d sec\n" , thisPrint ,newDate, (newDate.getTime()-lastDate.getTime())/1000);
//		  lastDate = newDate;
//		  ++lastPrint;
//	  }
//      attackDocument = wrappingOracle.getPossibility(i);
//	}

    }

    @Test
    public void samlSameIdTest() throws Exception {
        log.info("### Reading SAML message");
        SignatureManager manager = new SignatureManager();
        Document doc = DomUtilities.readDocument("src/test/resources/saml_same_id.xml");
        manager.setDocument(doc);
        assertEquals(1, manager.getSignatureElements().size());
        assertEquals(1, manager.getPayloads().size());

        Payload assertion = manager.getPayloads().get(0);
        assertion.setValue(assertion.getValue().replace("joe.user@example.com", "attacker@example.com"));

        WrappingOracle wrappingOracle = new WrappingOracle(doc, manager.getPayloads(), schemaAnalyser);
        assertTrue(wrappingOracle.maxPossibilities() > 0);
    }

    public void doGenericSignatureWrapping(SoapTestDocument soap,
      SignatureManager signatureManager,
      Signer s)
      throws Exception {
        doGenericSignatureWrapping(soap.getDocument(), signatureManager, s, false);
    }

    public void doGenericSignatureWrapping(Document doc,
      SignatureManager signatureManager,
      Signer s)
      throws Exception {
        doGenericSignatureWrapping(doc, signatureManager, s, false);
    }

    public void doGenericSignatureWrapping(SoapTestDocument soap,
      SignatureManager signatureManager,
      Signer s,
      boolean all)
      throws Exception {
        doGenericSignatureWrapping(soap.getDocument(), signatureManager, s, false);
    }

    public void doGenericSignatureWrapping(Document doc,
      SignatureManager signatureManager,
      Signer s,
      boolean all)
      throws Exception {
        List<Payload> payloads = signatureManager.getPayloads();
        assertNotNull(payloads);

        WrappingOracle wrappingOracle = new WrappingOracle(doc, signatureManager.getPayloads(), schemaAnalyser);

        String cmpDocument = domToString(doc);
        int max = wrappingOracle.maxPossibilities();
        assertTrue(max > 0);
        Document attackDocument = null;
        List<String> allMsgs = new ArrayList<String>();
        for (int i = 0; i < max; ++i) {
            attackDocument = wrappingOracle.getPossibility(i);
            // the original Document must not be changed
            assertEquals(cmpDocument, domToString(doc));
            // Verify Signature
            String attackDocumentAsString = domToString(attackDocument);
            // assertTrue("Invalid Message:\n" + domToString(attackDocument), attackDocumentAsString.contains(originalContent));
            // assertTrue("Invalid Message:\n" + domToString(attackDocument), attackDocumentAsString.contains(payloadContent));
            // System.out.println(attackDocumentAsString);
            //      for (Payload opt : payloads)
            //      {
            //        assertTrue("Invalid Message ("+i+"):\n" + domToString(attackDocument,true), attackDocumentAsString.contains(opt
            //            .getPayloadElement().getTextContent()));
            //      }
            // Abort in specific case
//        if( WeaknessLog.representation().contains("/soap:Envelope[1]/soap:Header[1]/wsu:Timestamp[1]")) {
//          if( WeaknessLog.representation().contains("/ds:Object[1]/")) {
//          System.out.println("###################### ATTENTION ###############");
//          System.out.println(WeaknessLog.representation());
//          System.out.println(DomUtilities.domToString(attackDocument,true));
//          return;
//          }
//        }
            if (log.isDebugEnabled()) {
                log.info("FINAL MESSAGE:\n\n" + domToString(attackDocument, true) + "\n\n");
                log.info("Now Validating");
            }
            boolean valid = false;
            try {
                valid = s.verifySignature(attackDocument);
            } catch (Exception e) {
                continue;
            }
            if (valid) {
                log.warn("\n#########################################################################\nSignature valid for i=" + i + "\n" + attackDocumentAsString);
                allMsgs.add(String.format("i=%d of %d\n%s\n\n%s", i + 1, wrappingOracle.maxPossibilities(), WeaknessLog.representation(), DomUtilities.domToString(attackDocument, true)));
                if (!all) {
                    return;
                }
            }
            // changed
        }
        if (allMsgs.isEmpty()) {
            fail("Could not find any wrapping attack.");
        } else {
            File f = new File("/tmp/run.txt");
            BufferedWriter bw = new BufferedWriter(new FileWriter(f));
            for (int i = 0; i < allMsgs.size(); ++i) {
                bw.write((i + 1) + ")\n" + allMsgs.get(i) + "\n");
            }
            bw.write("Found " + allMsgs.size() + " valid messages.");
            bw.close();
        }

    }
}
