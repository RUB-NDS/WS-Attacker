package wsattacker.plugin.signatureWrapping.test.singletests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.test.util.KeyInfoForTesting;
import wsattacker.plugin.signatureWrapping.test.util.Signer;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureManager;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.plugin.signatureWrapping.xpath.wrapping.WrappingOracle;

public class XPathNamespaceInjectionWeaknessTest
{

  @Test
  public void simpleTestBefore() throws Exception
  {
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
    
    List<OptionPayload> payloadList = sm.getPayloads();
    
    payloadList.get(0).parseValue(payloadList.get(0).getValueAsString().replace(orgContent, atkContent));
    
    WrappingOracle wo = new WrappingOracle(doc, payloadList, new SchemaAnalyzer());
    
    assertEquals(9*2*3, wo.maxPossibilities());
    
    List<Element> bodyChilds;
    bodyChilds = DomUtilities.getAllChildElements(soap.getBody());
    assertEquals(1, bodyChilds.size());
    
    String docBefore = DomUtilities.domToString(doc);
    
    Document attackDocument = wo.getPossibility(9*2*1+4);

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
