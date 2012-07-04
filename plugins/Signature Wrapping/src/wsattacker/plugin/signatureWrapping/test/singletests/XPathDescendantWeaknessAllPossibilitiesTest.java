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
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants;
import wsattacker.plugin.signatureWrapping.xpath.parts.AbsoluteLocationPath;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;
import wsattacker.plugin.signatureWrapping.xpath.weakness.XPathDescendantWeakness;

public class XPathDescendantWeaknessAllPossibilitiesTest extends XPathDescendantWeakness
{
  private static Step           descendantStep;
  private static Document       doc;
  private static Element        payloadElement;
  private static SchemaAnalyzerInterface schemaAnalyser;

  private List<String>      callList;

  public XPathDescendantWeaknessAllPossibilitiesTest() throws InvalidWeaknessException
  {
    super(descendantStep, doc, payloadElement, schemaAnalyser);
    callList = new ArrayList<String>();
  }

  @BeforeClass
  public static void setUpBeforeClass()
                                       throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();

    schemaAnalyser = new SchemaAnalyzer();
    schemaAnalyser.appendSchema(DomUtilities.readDocument("XML Schema/soap11.xsd"));
    // get signed element
    Element signedElement = soap.getDummyPayloadBody();
    String id = soap.getDummyPayloadBodyWsuId();
    String xpath = String.format("//*[@wsu:Id='%s']/x:y[@attr=\"foo\"]", id);

    doc = soap.getDocument();

    signedElement.setTextContent("Original Content");
// String fastXPathSignedPre = DomUtilities.getFastXPath(signedElement);

    // create payload element
    payloadElement = doc
        .createElementNS(NamespaceConstants.URI_NS_WSATTACKER, NamespaceConstants.PREFIX_NS_WSATTACKER + ":payloadBody");
    payloadElement.setTextContent("ATTACK");

    // 1) Build the XPathDescendantWeakness
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    descendantStep = abs.getRelativeLocationPaths().get(0);
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
    Logger.getLogger(getClass()).setLevel(Level.OFF);
  }

  @After
  public void tearDown()
                        throws Exception
  {
  }

  @Override
  protected void abuseWeakness(int wrapperPropertiesIndex,
                               int childIndex,
                               boolean useRealWrapper,
                               int postProcessListIndex,
                               int postProcessAbuseIndex,
                               Element signedElement,
                               Element payloadElement)
                                                      throws InvalidWeaknessException
  {
    String call = String
        .format("wpi=%d, child=%d, realWrapper=%b, postIndex=%d, postIndexAbuse=%d", wrapperPropertiesIndex, childIndex, useRealWrapper, postProcessListIndex, postProcessAbuseIndex);
    if (callList.contains(call))
    {
      callList.add("Already Contained:\n"+call);
      throw new InvalidWeaknessException("Already called: " + call);
    }
    callList.add(call);
    return;
  }

  @Test
  public void allPosibilites()
                              throws Exception
  {
    try
    {
      for (int i = 0; i < getNumberOfPossibilites(); ++i)
        abuseWeakness(i, null, payloadElement);
    }
    catch (Exception e)
    {
      throw e;
    }
    finally
    {
      Logger log = Logger.getLogger(getClass());
      log.setLevel(Level.INFO);
      StringBuffer buf = new StringBuffer();
      buf.append("All Calls:\n");
      for (int i=0; i<callList.size(); ++i)
      {
        buf.append(String.format("%2d ==> %s\n", i, callList.get(i)));
      }
      log.info(buf);
    }
    assertEquals((2 * 3 + 2 * 1 + 2 * 2) * (3 + 3), callList.size());
  }

}
