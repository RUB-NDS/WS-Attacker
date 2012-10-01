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
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzer;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

public class SchemaTest
{

  private static Logger         log;
  private static SchemaAnalyzer sa;

  @BeforeClass
  public static void setUpBeforeClass()
                                       throws Exception
  {
    sa = new SchemaAnalyzer();
    // Logger
    log = Logger.getLogger(sa.getClass());
    log.setLevel(Level.ALL);

    // Load Schema Files
    final String schemaDir = "src/main/resources/XML Schema";
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
        sa.appendSchema(xsd);
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
    log.setLevel(Level.ALL);
  }

  @After
  public void tearDown()
                        throws Exception
  {
  }

  @Test
  public void testCorrespondingElement()
  {
    SoapTestDocument cmpDoc, newDoc;
    Element cmpElement, newElement;
    String cmpXPath, newXPath;

    // Security: Depth = 1
    cmpDoc = new SoapTestDocument();
    cmpElement = cmpDoc.getSucurity();
    cmpXPath = DomUtilities.getFastXPath(cmpElement);

    newDoc = new SoapTestDocument();

    assertTrue(!cmpDoc.toString().equals(newDoc.toString()));
    newElement = DomUtilities.findCorrespondingElement(newDoc.getDocument(), cmpElement);
    assertEquals(cmpDoc.toString(), newDoc.toString());
    newXPath = DomUtilities.getFastXPath(newElement);
    assertEquals(cmpXPath, newXPath);
    assertNotSame(cmpElement.getOwnerDocument(), newElement.getOwnerDocument());

    // SIgnature: Depth = 2;
    cmpDoc = new SoapTestDocument();
    cmpElement = cmpDoc.getSignature();
    cmpXPath = DomUtilities.getFastXPath(cmpElement);

    newDoc = new SoapTestDocument();

    assertTrue(!cmpDoc.toString().equals(newDoc.toString()));
    newElement = DomUtilities.findCorrespondingElement(newDoc.getDocument(), cmpElement);
    assertEquals(cmpDoc.toString(), newDoc.toString());
    newXPath = DomUtilities.getFastXPath(newElement);
    assertEquals(cmpXPath, newXPath);
    assertNotSame(cmpElement.getOwnerDocument(), newElement.getOwnerDocument());

  }

  @Test
  public void testFindExpansionPoint()
  {
    SoapTestDocument s;
    List<AnyElementPropertiesInterface> result;
    List<String> cmp;
    List<QName> filterList;

    log.setLevel(Level.INFO);

    s = new SoapTestDocument(); // Soap11
    cmp = new ArrayList<String>();
    cmp.add(s.getEnvelope().getNodeName());
    cmp.add(s.getBody().getNodeName());
    cmp.add(s.getHeader().getNodeName());

    assertFalse("New Analysing Doc must be created", sa.isInCurrentAnalysis(s.getEnvelope()));

    assertNotNull(sa.getSchema());
    result = sa.findExpansionPoint(s.getEnvelope());
    // Compare results
    assertEquals(cmp.size(), result.size()); // same size
    for (AnyElementPropertiesInterface prop : result)
      assertTrue(cmp.contains(prop.getDocumentElement().getNodeName())); // all elements contained

    s = new SoapTestDocument(URI_NS_SOAP_1_2_ENVELOPE); // Soap12
    cmp = new ArrayList<String>();
    cmp.add(s.getBody().getNodeName());
    cmp.add(s.getHeader().getNodeName());

    assertFalse("New Analysing Doc must be created", sa.isInCurrentAnalysis(s.getEnvelope()));
    result = sa.findExpansionPoint(s.getEnvelope());
    // Compare results
    assertEquals(cmp.size(), result.size()); // same size
    for (AnyElementPropertiesInterface prop : result)
      assertTrue(cmp.contains(prop.getDocumentElement().getNodeName())); // all elements contained

    s = new SoapTestDocument(URI_NS_SOAP_1_2_ENVELOPE); // Soap12
    cmp = new ArrayList<String>();
    cmp.add(s.getBody().getNodeName());
    cmp.add(s.getHeader().getNodeName());
    cmp.add("ds:Object");
    cmp.add("wsse:Security");

    s.getSignature();

// log.setLevel(Level.ALL);
    filterList = new ArrayList<QName>();
    sa.setFilterList(filterList);
    filterList.add(new QName(URI_NS_DS, "SignedInfo"));
    filterList.add(new QName(URI_NS_DS, "KeyInfo"));
    filterList.add(new QName(URI_NS_DS, "SignatureValue"));

    assertFalse("New Analysing Doc must be created", sa.isInCurrentAnalysis(s.getEnvelope()));
    result = sa.findExpansionPoint(s.getEnvelope());
    assertTrue("No new Analysing Doc must be created", sa.isInCurrentAnalysis(s.getEnvelope()));
    result = sa.findExpansionPoint(s.getEnvelope()); // Double Test
    // Compare results
    assertEquals(cmp.size(), result.size()); // same size
    for (AnyElementPropertiesInterface prop : result)
      assertTrue(cmp.contains(prop.getDocumentElement().getNodeName())); // all elements contained

    sa.setFilterList(new ArrayList<QName>()); // no filter
    // Same Test as above, just because last test reused old Document
    s = new SoapTestDocument(); // Soap11
    cmp = new ArrayList<String>();
    cmp.add(s.getEnvelope().getNodeName());
    cmp.add(s.getBody().getNodeName());
    cmp.add(s.getHeader().getNodeName());

    assertFalse("New Analysing Doc must be created", sa.isInCurrentAnalysis(s.getEnvelope()));
    result = sa.findExpansionPoint(s.getEnvelope());
    // Compare results
    assertEquals(cmp.size(), result.size()); // same size
    for (AnyElementPropertiesInterface prop : result)
      assertTrue(cmp.contains(prop.getDocumentElement().getNodeName())); // all elements contained
  }

}
