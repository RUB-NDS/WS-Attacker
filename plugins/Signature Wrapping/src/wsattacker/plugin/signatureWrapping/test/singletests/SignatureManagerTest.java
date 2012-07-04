package wsattacker.plugin.signatureWrapping.test.singletests;

import static org.junit.Assert.*;

import java.util.*;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;

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
    Document doc = DomUtilities.readDocument("signed_rampart_message.xml");
    manager.setDocument(doc);
    SignatureElement sig = manager.getSignatureElement();
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
    Document doc = DomUtilities.readDocument("signed_xspres_message.xml");
    manager.setDocument(doc);
    SignatureElement sig = manager.getSignatureElement();
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

}
