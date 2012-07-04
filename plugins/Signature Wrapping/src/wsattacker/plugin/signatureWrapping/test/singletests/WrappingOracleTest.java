package wsattacker.plugin.signatureWrapping.test.singletests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.domToString;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
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
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.test.util.KeyInfoForTesting;
import wsattacker.plugin.signatureWrapping.test.util.Signer;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.test.util.WsuURIDereferencer;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants;
import wsattacker.plugin.signatureWrapping.util.signature.ReferenceElement;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureManager;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.plugin.signatureWrapping.xpath.wrapping.WrappingOracle;

public class WrappingOracleTest
{

  public static SchemaAnalyzerInterface schemaAnalyser;
  public static Logger         log;

  @BeforeClass
  public static void setUpBeforeClass()
                                       throws Exception
  {
    schemaAnalyser = new SchemaAnalyzer();
    // Logger
    log = Logger.getLogger(WrappingOracle.class);
    Logger.getLogger("wsattacker.plugin.signaturewrapping.util.signature").setLevel(Level.WARN);
    Logger.getLogger("wsattacker.plugin.signaturewrapping.test.util").setLevel(Level.WARN);
    Logger.getLogger(WsuURIDereferencer.class).setLevel(Level.WARN);
    Logger.getLogger(DomUtilities.class).setLevel(Level.WARN);
    Logger.getLogger(WrappingOracle.class).setLevel(Level.WARN);
// Logger.getLogger("wsattacker.plugin.signaturewrapping.util.wrapping").setLevel(Level.TRACE);

// log.setLevel(Level.ALL);
    Logger.getLogger("wsattacker.plugin.signatureWrapping.schema.SchemaAnalyser").setLevel(Level.WARN);

    // Load Schema Files
    final String schemaDir = "XML Schema";
    File folder = new File(schemaDir);
    File[] listOfFiles = folder.listFiles();

    for (File cur : listOfFiles)
    {
      if (cur.isFile() && cur.toString().endsWith(".xsd"))
      {
// System.out.println("Using File '"+cur+"'");
        Document xsd;
        try
        {
          xsd = DomUtilities.readDocument(cur.toString());
        }
        catch (Exception e)
        {
          e.printStackTrace();
          System.err.println("Could not read: " + cur.toString());
          continue;
        }
        schemaAnalyser.appendSchema(xsd);
      }
    }
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
    log.setLevel(Level.OFF);
  }

  @After
  public void tearDown()
                        throws Exception
  {
  }

  @Test
  public void testAutomaticReferencedBasedSignatureWrapping11()
                                                               throws Exception
  {
    log.info("### SOAP 1.1 TEST ###");
    SoapTestDocument soap;
    soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_1_ENVELOPE);
    testAutomaticReferencedBasedSignatureWrapping(soap);

  }

  @Test
  public void testAutomaticReferencedBasedSignatureWrapping12()
                                                               throws Exception
  {
    log.info("### SOAP 1.2 TEST ###");
    SoapTestDocument soap;
    soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_2_ENVELOPE);
    testAutomaticReferencedBasedSignatureWrapping(soap);

  }

  public void testAutomaticReferencedBasedSignatureWrapping(SoapTestDocument soap)
                                                                                  throws Exception
  {

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

    List<OptionPayload> payloads = signatureManager.getPayloads();
    assertNotNull(payloads);
    assertEquals(1, payloads.size());
    OptionPayload optionPayload = payloads.get(0);
    assertTrue(optionPayload.getReferringElement() instanceof ReferenceElement);
    assertEquals(toSign.get(0), ((ReferenceElement) optionPayload.getReferringElement()).getURI());

    String thePayload = domToString(soap.getDummyPayloadBody()).replace(originalContent, payloadContent);
    assertTrue(optionPayload.isValid(thePayload));
    assertTrue(optionPayload.parseValue(thePayload));

    WrappingOracle wrappingOracle = new WrappingOracle(soap.getDocument(), signatureManager.getPayloads(), schemaAnalyser);

    int max = wrappingOracle.maxPossibilities();
    assertTrue(max > 0);
    Document attackDocument = null;
    for (int i = 0; i < max; ++i)
    {
      attackDocument = wrappingOracle.getPossibility(i);
      assertEquals(cmpDocument, domToString(soap.getDocument())); // the original Document must not be
      // Verify Signature
      String attackDocumentAsString = domToString(attackDocument);
      assertTrue("Invalid Message:\n" + domToString(attackDocument), attackDocumentAsString.contains(originalContent));
      assertTrue("Invalid Message:\n" + domToString(attackDocument), attackDocumentAsString.contains(payloadContent));
// System.out.println(attackDocumentAsString);
      if (log.isDebugEnabled())
      {
        log.info("FINAL MESSAGE:\n\n" + domToString(attackDocument, true) + "\n\n");
        log.info("Now Validating");
      }
      boolean valid = s.verifySignature(attackDocument);
      if (valid)
      {
        log.warn("\n#########################################################################\nSignature valid for i=" + i + "\n" + attackDocumentAsString);
        return;
      }
// changed
    }
    fail("Could not find any wrapping attack. None of the " + wrappingOracle.maxPossibilities() + " worked.");
  }

  @Test
  public void testAutomaticXPathBasedSignatureWrapping()
                                                        throws Exception
  {

    SoapTestDocument soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_2_ENVELOPE);

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

    List<OptionPayload> payloads = signatureManager.getPayloads();
    OptionPayload optionPayload = payloads.get(0);

    String thePayload = domToString(soap.getDummyPayloadBody()).replace(originalContent, payloadContent);
    assertTrue(optionPayload.isValid(thePayload));
    assertTrue(optionPayload.parseValue(thePayload));

    assertEquals(toSign.size(), payloads.size());

    doGenericSignatureWrapping(soap, signatureManager, s);
  }

  @Test
  public void testAutomaticMultipleXPathBasedSignatureWrapping()
                                                                throws Exception
  {

    SoapTestDocument soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_2_ENVELOPE);

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

    List<OptionPayload> payloads = signatureManager.getPayloads();
    for (OptionPayload optionPayload : payloads)
    {
      String thePayload = domToString(optionPayload.getSignedElement()).replace(originalContent, payloadContent);
      assertTrue(optionPayload.isValid(thePayload));
      assertTrue(optionPayload.parseValue(thePayload));
    }

    assertEquals(toSign.size(), payloads.size());

    doGenericSignatureWrapping(soap, signatureManager, s);
  }

  @Test
  public void specialTest() throws Exception {
    SignatureManager signatureManager = new SignatureManager();
    Document doc =  DomUtilities.readDocument("signed_rampart_message_soap_1.2.xml");
    signatureManager.setDocument(doc);
    OptionPayload bodyPayload = signatureManager.getPayloads().get(0);
    bodyPayload.parseValue(bodyPayload.getValueAsString().replace("ORIGINAL", "ATTACKER"));
    WrappingOracle wrappingOracle = new WrappingOracle(doc, signatureManager.getPayloads(), schemaAnalyser);
//    Document attackDocument = wrappingOracle.getPossibility(67);
    for(int i=0; i<wrappingOracle.maxPossibilities(); ++i)
    {
      System.out.println(i+"/"+wrappingOracle.maxPossibilities());
      wrappingOracle.getPossibility(i);
    }
  }
  
  @Test
  public void testFeaturedSignatureWrapping()
                                                        throws Exception
  {

    SoapTestDocument soap = new SoapTestDocument(NamespaceConstants.URI_NS_SOAP_1_2_ENVELOPE);

    String originalContent = "Original Content";
    String payloadContent = "ATTACK CONTENT";
    Element firstBodyChild = soap.getDummyPayloadBody();
    Element signed = soap.getDocument().createElementNS(firstBodyChild.getNamespaceURI(), firstBodyChild.getPrefix()+":signedElement");
    firstBodyChild.appendChild(signed);
    signed.setTextContent(originalContent);
    // create an expired timestamp
    soap.setTimestamp(true, true);

    List<String> toSign = new ArrayList<String>();
    // Declare this as "toSign"
    toSign.add("//wsu:Timestamp[1]");
    toSign.add("//"+firstBodyChild.getNodeName()+"[@wsu:Id='"+soap.getDummyPayloadBodyWsuId()+"']/"+signed.getNodeName()+"[1]");
    Signer s = new Signer(new KeyInfoForTesting());
//    System.out.println(soap);
    s.sign(soap.getDocument(), toSign);
    System.out.println(soap);

    SignatureManager signatureManager = new SignatureManager();
    signatureManager.setDocument(soap.getDocument());

    List<OptionPayload> payloads = signatureManager.getPayloads();
    OptionPayload optionPayload = payloads.get(1);

    String thePayload = domToString(signed).replace(originalContent, payloadContent);
    assertTrue(optionPayload.isValid(thePayload));
    assertTrue(optionPayload.parseValue(thePayload));

    assertEquals(toSign.size(), payloads.size());

    doGenericSignatureWrapping(soap, signatureManager, s, true);
  }

  public void doGenericSignatureWrapping(SoapTestDocument soap,
                                         SignatureManager signatureManager,
                                         Signer s)
                                                  throws Exception
  {
    doGenericSignatureWrapping(soap, signatureManager, s, false);
  }
  public void doGenericSignatureWrapping(SoapTestDocument soap,
                                           SignatureManager signatureManager,
                                           Signer s,
                                           boolean all)
                                                    throws Exception
    {
      List<OptionPayload> payloads = signatureManager.getPayloads();
      assertNotNull(payloads);
  
      WrappingOracle wrappingOracle = new WrappingOracle(soap.getDocument(), signatureManager.getPayloads(), schemaAnalyser);
  
      String cmpDocument = domToString(soap.getDocument());
      int max = wrappingOracle.maxPossibilities();
      assertTrue(max > 0);
      Document attackDocument = null;
      List<String> allMsgs = new ArrayList<String>();
      for (int i = 0; i < max; ++i)
      {
        attackDocument = wrappingOracle.getPossibility(i);
        // the original Document must not be changed
        assertEquals(cmpDocument, domToString(soap.getDocument()));
        // Verify Signature
        String attackDocumentAsString = domToString(attackDocument);
  // assertTrue("Invalid Message:\n" + domToString(attackDocument), attackDocumentAsString.contains(originalContent));
  // assertTrue("Invalid Message:\n" + domToString(attackDocument), attackDocumentAsString.contains(payloadContent));
  // System.out.println(attackDocumentAsString);
  //      for (OptionPayload opt : payloads)
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
        if (log.isDebugEnabled())
        {
          log.info("FINAL MESSAGE:\n\n" + domToString(attackDocument, true) + "\n\n");
          log.info("Now Validating");
        }
       boolean valid = s.verifySignature(attackDocument);
        if (valid)
        {
          log.warn("\n#########################################################################\nSignature valid for i=" + i + "\n" + attackDocumentAsString);
          allMsgs.add(String.format("i=%d of %d\n%s\n\n%s",i+1,wrappingOracle.maxPossibilities(), WeaknessLog.representation(),DomUtilities.domToString(attackDocument,true)));
          if (!all)
            return;
        }
  // changed
      }
      if(allMsgs.isEmpty())
        fail("Could not find any wrapping attack.");
      else {
        File f = new File("/tmp/run.txt");
        BufferedWriter bw = new BufferedWriter(new FileWriter(f));
        for(int i=0; i<allMsgs.size(); ++i)
          bw.write((i+1)+")\n"+allMsgs.get(i)+"\n");
        bw.write("Found "+allMsgs.size()+" valid messages.");
        bw.close();
      }
      
    }

}
