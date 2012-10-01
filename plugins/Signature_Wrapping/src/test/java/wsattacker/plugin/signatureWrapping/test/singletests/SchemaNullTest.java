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

import javax.xml.namespace.QName;

import org.junit.Test;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface;
import wsattacker.plugin.signatureWrapping.schema.NullSchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

public class SchemaNullTest
{

  @Test
  public void simpleTest() {
    SoapTestDocument soap = new SoapTestDocument();
    soap.getDummyPayloadBody();
    
    SchemaAnalyzerInterface sa = new NullSchemaAnalyzer();
    
    List<AnyElementPropertiesInterface> result = sa.findExpansionPoint(soap.getEnvelope());
    
    List<Element> childElementList = DomUtilities.getAllChildElements(soap.getEnvelope(), true);
    childElementList.add(0, soap.getEnvelope());
    List<String> fastXPathList = DomUtilities.nodelistToFastXPathList(childElementList);
    

    assertEquals(childElementList.size(), result.size());
    assertEquals(fastXPathList.size(), result.size());
    
    List<String> contained = new ArrayList<String>();
    for(AnyElementPropertiesInterface any : result) {
      String fxp = DomUtilities.getFastXPath(any.getDocumentElement());
      assertTrue(fastXPathList.contains(fxp));
      assertTrue(!contained.contains(fxp));
      contained.add(fxp);
    }
  }
  

  @Test
  public void filterTest() {
    SoapTestDocument soap = new SoapTestDocument();
    soap.getDummyPayloadBody();
    
    SchemaAnalyzerInterface sa = new NullSchemaAnalyzer();
    
    // Filter...
    List<QName> filterList = new ArrayList<QName>();
    filterList.add(new QName(soap.getBody().getNamespaceURI(), soap.getBody().getLocalName(), soap.getBody().getPrefix()));
    sa.setFilterList(filterList);
    
    List<AnyElementPropertiesInterface> result = sa.findExpansionPoint(soap.getEnvelope());
    
    List<Element> childElementList = new ArrayList<Element>();
    childElementList.add(soap.getEnvelope());
    childElementList.add(soap.getHeader());
    
    List<String> fastXPathList = DomUtilities.nodelistToFastXPathList(childElementList);
    

    assertEquals(childElementList.size(), result.size());
    assertEquals(fastXPathList.size(), result.size());
    
    List<String> contained = new ArrayList<String>();
    for(AnyElementPropertiesInterface any : result) {
      String fxp = DomUtilities.getFastXPath(any.getDocumentElement());
      assertTrue(fastXPathList.contains(fxp));
      assertTrue(!contained.contains(fxp));
      contained.add(fxp);
    }
  }

}
