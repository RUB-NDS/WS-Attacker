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

import java.util.List;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.schema.NullSchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.signature.ReferringElementInterface;
import wsattacker.plugin.signatureWrapping.util.signature.SignatureManager;
import wsattacker.plugin.signatureWrapping.xpath.parts.AbsoluteLocationPath;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;
import wsattacker.plugin.signatureWrapping.xpath.weakness.XPathAttributeWeakness;
import wsattacker.plugin.signatureWrapping.xpath.weakness.XPathDescendantWeakness;
import wsattacker.plugin.signatureWrapping.xpath.wrapping.WrappingOracle;

public class XPathAttributeWeaknessTest
{

  @Test
  public void simpleTestBefore() throws Exception
  {
    String orgContent = "ORIGINAL CONTENT";
    String atkContent = "ATTACKER CONTENT";
    SoapTestDocument soap = new SoapTestDocument();
    Element signed = soap.getDummyPayloadBody();
    signed.setTextContent(orgContent);
    String id = soap.getDummyPayloadBodyWsuId();
    
    Element payload = (Element) signed.cloneNode(true);
    payload.setTextContent(atkContent);
    
    String xpath = DomUtilities.getFastXPath(signed).replaceAll("\\[1\\]", "") + "[@wsu:Id='"+id+"']";
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    Step step = abs.getRelativeLocationPaths().get(2);
    XPathAttributeWeakness aw = new XPathAttributeWeakness(step, signed, payload);
    
    assertEquals(2*3*1, aw.getNumberOfPossibilites());
    
    List<Element> bodyChilds;
    bodyChilds = DomUtilities.getAllChildElements(soap.getBody());
    assertEquals(1, bodyChilds.size());
    
    aw.abuseWeakness(0, signed, payload);
    
    bodyChilds = DomUtilities.getAllChildElements(soap.getBody());
    assertEquals(2, bodyChilds.size());
    
    String xml = soap.toString();
    int orgPos = xml.indexOf(orgContent);
    int atkPos = xml.indexOf(atkContent);
    assertTrue(orgPos > 0);
    assertTrue(atkPos > 0);
    assertTrue(atkPos < orgPos);
  }

  @Test
  public void simpleTestAfter() throws Exception
  {
    String orgContent = "ORIGINAL CONTENT";
    String atkContent = "ATTACKER CONTENT";
    SoapTestDocument soap = new SoapTestDocument();
    Element signed = soap.getDummyPayloadBody();
    signed.setTextContent(orgContent);
    String id = soap.getDummyPayloadBodyWsuId();
    
    Element payload = (Element) signed.cloneNode(true);
    payload.setTextContent(atkContent);
    
    String xpath = DomUtilities.getFastXPath(signed).replaceAll("\\[1\\]", "") + "[@wsu:Id='"+id+"']";
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    Step step = abs.getRelativeLocationPaths().get(2);
    XPathAttributeWeakness aw = new XPathAttributeWeakness(step, signed, payload);
    
    assertEquals(2*3*1, aw.getNumberOfPossibilites());
    
    List<Element> bodyChilds;
    bodyChilds = DomUtilities.getAllChildElements(soap.getBody());
    assertEquals(1, bodyChilds.size());
    
    aw.abuseWeakness(3, signed, payload);
    
    bodyChilds = DomUtilities.getAllChildElements(soap.getBody());
    assertEquals(2, bodyChilds.size());
    
    String xml = soap.toString();
    int orgPos = xml.indexOf(orgContent);
    int atkPos = xml.indexOf(atkContent);
    assertTrue(orgPos > 0);
    assertTrue(atkPos > 0);
    assertTrue(atkPos > orgPos);
  }

  @Test
  public void simpleTestAttributeInMiddle() throws Exception
  {
    String orgContent = "ORIGINAL CONTENT";
    String atkContent = "ATTACKER CONTENT";
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();
    Element signed = doc.createElement("xyz");
    soap.getDummyPayloadBody().appendChild(signed);
    signed.setTextContent(orgContent);
    String id = soap.getDummyPayloadBodyWsuId();
    
    Element payload = (Element) signed.cloneNode(true);
    payload.setTextContent(atkContent);
    
    String xpath = DomUtilities.getFastXPath(soap.getDummyPayloadBody()).replaceAll("\\[1\\]", "") + "[@wsu:Id='"+id+"']/" + signed.getNodeName();
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    Step step = abs.getRelativeLocationPaths().get(2);
    XPathAttributeWeakness aw = new XPathAttributeWeakness(step, signed, payload);
    
    assertEquals(2*3*1, aw.getNumberOfPossibilites());
    
    List<Element> bodyChilds;
    bodyChilds = DomUtilities.getAllChildElements(soap.getBody());
    assertEquals(1, bodyChilds.size());
    
    aw.abuseWeakness(0, signed, payload);
    System.out.println(soap);
    
    bodyChilds = DomUtilities.getAllChildElements(soap.getBody());
    assertEquals(2, bodyChilds.size());
    
    String xml = soap.toString();
    int orgPos = xml.indexOf(orgContent);
    int atkPos = xml.indexOf(atkContent);
    assertTrue(orgPos > 0);
    assertTrue(atkPos > 0);
    assertTrue(atkPos < orgPos);
  }
}
