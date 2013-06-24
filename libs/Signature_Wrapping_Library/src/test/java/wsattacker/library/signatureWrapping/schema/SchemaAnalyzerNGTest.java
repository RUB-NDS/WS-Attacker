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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.library.signatureWrapping.schema;

import java.util.*;
import javax.xml.namespace.QName;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.signatureWrapping.util.SoapTestDocument;
import wsattacker.library.signatureWrapping.util.dom.DomUtilities;
import static wsattacker.library.signatureWrapping.util.signature.NamespaceConstants.PREFIX_NS_SAMLP;
import static wsattacker.library.signatureWrapping.util.signature.NamespaceConstants.PREFIX_NS_SOAP_1_1;
import static wsattacker.library.signatureWrapping.util.signature.NamespaceConstants.PREFIX_NS_SOAP_1_2;
import static wsattacker.library.signatureWrapping.util.signature.NamespaceConstants.URI_NS_DS;
import static wsattacker.library.signatureWrapping.util.signature.NamespaceConstants.URI_NS_SAML20;
import static wsattacker.library.signatureWrapping.util.signature.NamespaceConstants.URI_NS_SAML20P;
import static wsattacker.library.signatureWrapping.util.signature.NamespaceConstants.URI_NS_SOAP_1_1;
import static wsattacker.library.signatureWrapping.util.signature.NamespaceConstants.URI_NS_SOAP_1_2;

/**
 *
 * @author christian
 */
public class SchemaAnalyzerNGTest {

    private static Document DOC_SAML20, DOC_SAML20P, DOC_SOAP11, DOC_SOAP12, DOC_DS, DOC_XPATH, DOC_WSSE10, DOC_WSSE11;

    public SchemaAnalyzerNGTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
        DOC_SAML20 = SchemaAnalyzerFactory.getSchemaDocument("saml20.xsd");
        DOC_SAML20P = SchemaAnalyzerFactory.getSchemaDocument("saml20p.xsd");
        DOC_SOAP11 = SchemaAnalyzerFactory.getSchemaDocument("soap11.xsd");
        DOC_SOAP12 = SchemaAnalyzerFactory.getSchemaDocument("soap12.xsd");
        DOC_DS = SchemaAnalyzerFactory.getSchemaDocument("xmldsig-core-schema.xsd");
        DOC_XPATH = SchemaAnalyzerFactory.getSchemaDocument("xmldsig-filter2.xsd");
        DOC_WSSE10 = SchemaAnalyzerFactory.getSchemaDocument("wssec-1.0.xsd");
        DOC_WSSE11 = SchemaAnalyzerFactory.getSchemaDocument("wssec-1.1.xsd");
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of getExpandedAnalyzingDocument method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testGetExpandedAnalyzingDocument() throws Exception {
        System.out.println("getExpandedAnalyzingDocument");
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SOAP11);

        Document toTest = DomUtilities.stringToDom("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"></soapenv:Envelope>");

        SoapTestDocument expandedSoap = new SoapTestDocument();
        expandedSoap.getHeader();
        expandedSoap.getBody();
        Document expResult = expandedSoap.getDocument();

        String nonExpandedSoap = DomUtilities.domToString(toTest.getDocumentElement(), false);

        instance.findExpansionPoint(toTest.getDocumentElement());

        Document result = instance.getExpandedAnalyzingDocument();
        assertEquals("Did not get expected expanded document", DomUtilities.domToString(expResult, false), DomUtilities.domToString(result, false));

        assertEquals("Analysing Document should not be touched", nonExpandedSoap, DomUtilities.domToString(toTest, false));
    }

    /**
     * Test of getAnalyzingDocument method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testGetAnalyzingDocument() {
        System.out.println("getAnalyzingDocument");
        SoapTestDocument soap = new SoapTestDocument(URI_NS_SOAP_1_1);
        Element root = soap.getEnvelope();
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.findExpansionPoint(root);
        assertEquals(soap.getDocument(), instance.getAnalyzingDocument());
    }

    /**
     * Test of appendSchema method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testAppendSchemaAndClearSchema() throws Exception {
        System.out.println("appendSchema");
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        assertEquals(0, instance.schemaMap.size());
        Document newSchema;

        newSchema = SchemaAnalyzerFactory.getSchemaDocument("saml20.xsd");
        instance.appendSchema(newSchema);
        assertEquals(1, instance.schemaMap.size());
        assertTrue(instance.schemaMap.containsValue(newSchema));
        assertTrue(instance.schemaMap.containsKey(URI_NS_SAML20));

        newSchema = SchemaAnalyzerFactory.getSchemaDocument("saml20.xsd");
        instance.appendSchema(newSchema);
        assertEquals(1, instance.schemaMap.size());

        newSchema = SchemaAnalyzerFactory.getSchemaDocument("saml20p.xsd");
        instance.appendSchema(newSchema);
        assertEquals(2, instance.schemaMap.size());
        assertTrue(instance.schemaMap.containsValue(newSchema));
        assertTrue(instance.schemaMap.containsKey(URI_NS_SAML20P));

        instance.clearSchemas();
        assertEquals(0, instance.schemaMap.size());
    }

    /**
     * Test of isInCurrentAnalysis method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testIsInCurrentAnalysis() {
        System.out.println("isInCurrentAnalysis");
        SoapTestDocument soap = new SoapTestDocument(URI_NS_SOAP_1_1);
        soap.getHeader();
        soap.getBody();
        Element root = soap.getEnvelope();
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.findExpansionPoint(root);
        assertTrue(instance.isInCurrentAnalysis(root));
        soap = new SoapTestDocument(URI_NS_SOAP_1_1);
        soap.getHeader();
        soap.getBody();
        assertTrue(instance.isInCurrentAnalysis(soap.getEnvelope()));
        soap = new SoapTestDocument(URI_NS_SOAP_1_2);
        soap.getHeader();
        soap.getBody();
        assertFalse(instance.isInCurrentAnalysis(soap.getEnvelope()));
    }

    /**
     * Test of findExpansionPoint method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testFindExpansionPoint_Soap11() throws Exception {
        System.out.println("findExpansionPoint");

//        SoapTestDocument soap = new SoapTestDocument(URI_NS_SOAP_1_1);
//        Element fromHere = soap.getEnvelope();
        Element fromHere = DomUtilities.stringToDom("<" + PREFIX_NS_SOAP_1_1 + ":Envelope xmlns:" + PREFIX_NS_SOAP_1_1 + "=\"" + URI_NS_SOAP_1_1 + "\"></" + PREFIX_NS_SOAP_1_1 + ":Envelope>").getDocumentElement();
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SOAP11);

        Set<AnyElementPropertiesInterface> result = instance.findExpansionPoint(fromHere);

        Set<String> expectedResult = new HashSet<String>();
        expectedResult.add(URI_NS_SOAP_1_1 + ":" + PREFIX_NS_SOAP_1_1 + ":" + "Envelope");
        expectedResult.add(URI_NS_SOAP_1_1 + ":" + PREFIX_NS_SOAP_1_1 + ":" + "Body");
        expectedResult.add(URI_NS_SOAP_1_1 + ":" + PREFIX_NS_SOAP_1_1 + ":" + "Header");

        assertEquals(expectedResult.size(), result.size());

        Set<String> gotResult = new HashSet<String>();
        for (AnyElementPropertiesInterface any : result) {
            Element extensionPoint = any.getDocumentElement();
            gotResult.add(extensionPoint.getNamespaceURI() + ":" + extensionPoint.getNodeName());
        }
        assertEquals(expectedResult, gotResult);
    }

    /**
     * Test of findExpansionPoint method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testFindExpansionPoint_Soap12() throws Exception {
        System.out.println("findExpansionPoint");

//        SoapTestDocument soap = new SoapTestDocument(URI_NS_SOAP_1_1);
//        Element fromHere = soap.getEnvelope();
        Element fromHere = DomUtilities.stringToDom("<" + PREFIX_NS_SOAP_1_2 + ":Envelope xmlns:" + PREFIX_NS_SOAP_1_2 + "=\"" + URI_NS_SOAP_1_2 + "\"></" + PREFIX_NS_SOAP_1_2 + ":Envelope>").getDocumentElement();
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SOAP12);

        Set<AnyElementPropertiesInterface> result = instance.findExpansionPoint(fromHere);

        Set<String> expectedResult = new HashSet<String>();
        expectedResult.add(URI_NS_SOAP_1_2 + ":" + PREFIX_NS_SOAP_1_2 + ":" + "Body");
        expectedResult.add(URI_NS_SOAP_1_2 + ":" + PREFIX_NS_SOAP_1_2 + ":" + "Header");

        assertEquals(expectedResult.size(), result.size());

        Set<String> gotResult = new HashSet<String>();
        for (AnyElementPropertiesInterface any : result) {
            Element extensionPoint = any.getDocumentElement();
            gotResult.add(extensionPoint.getNamespaceURI() + ":" + extensionPoint.getNodeName());
        }
        assertEquals(expectedResult, gotResult);
    }

    @Test
    public void testFindExpansionPoint() {
        SchemaAnalyzerNG sa = new SchemaAnalyzerNG();
        sa.appendSchema(DOC_SOAP11);
        sa.appendSchema(DOC_SOAP12);
        sa.appendSchema(DOC_DS);
        sa.appendSchema(DOC_XPATH);
        sa.appendSchema(DOC_WSSE10);
        sa.appendSchema(DOC_WSSE11);
        SoapTestDocument s;
        Set<AnyElementPropertiesInterface> result;
        List<String> cmp;
        List<QName> filterList;

        s = new SoapTestDocument(URI_NS_SOAP_1_1);
        cmp = new ArrayList<String>();
        cmp.add(s.getEnvelope().getNodeName());
        cmp.add(s.getBody().getNodeName());
        cmp.add(s.getHeader().getNodeName());

        assertFalse("New Analysing Doc must be created", sa.isInCurrentAnalysis(s.getEnvelope()));

        result = sa.findExpansionPoint(s.getEnvelope());
        // Compare results
        assertEquals(cmp.size(), result.size()); // same size
        for (AnyElementPropertiesInterface prop : result) {
            assertTrue(cmp.contains(prop.getDocumentElement().getNodeName())); // all elements contained
        }
        s = new SoapTestDocument(URI_NS_SOAP_1_2);
        cmp = new ArrayList<String>();
        cmp.add(s.getBody().getNodeName());
        cmp.add(s.getHeader().getNodeName());

        assertFalse("New Analysing Doc must be created", sa.isInCurrentAnalysis(s.getEnvelope()));
        result = sa.findExpansionPoint(s.getEnvelope());
        // Compare results
        assertEquals(cmp.size(), result.size()); // same size
        for (AnyElementPropertiesInterface prop : result) {
            assertTrue(cmp.contains(prop.getDocumentElement().getNodeName())); // all elements contained
        }
        s = new SoapTestDocument(URI_NS_SOAP_1_2); // Soap12
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
        assertEquals("Not all expected elements contained: " + result.toString(), cmp.size(), result.size()); // same size
        for (AnyElementPropertiesInterface prop : result) {
            assertTrue(cmp.contains(prop.getDocumentElement().getNodeName())); // all elements contained
        }
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
        for (AnyElementPropertiesInterface prop : result) {
            assertTrue(cmp.contains(prop.getDocumentElement().getNodeName())); // all elements contained
        }
    }

    /**
     * Test of findPossibleChildElements method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testFindPossibleChildElements_Element() throws Exception {
        System.out.println("findPossibleChildElements: Envelope 11 (Element)");
        SoapTestDocument soap = new SoapTestDocument(URI_NS_SOAP_1_1);
        Element element = soap.getEnvelope();
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SOAP11);
        List<Element> expectedResult;
        expectedResult = (List<Element>) DomUtilities.evaluateXPath(DOC_SOAP11,
          "//*[local-name()='complexType' and @name='Envelope']//*[local-name()='any']");
        expectedResult.addAll((List<Element>) DomUtilities.evaluateXPath(DOC_SOAP11,
          "//*[local-name()='element'][@name='Header' or @name='Body']"));
        List<Element> foundResult = instance.findPossibleChildElements(element);
        assertEquals(expectedResult, foundResult);
    }

    /**
     * Test of findPossibleChildElements method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testFindPossibleChildElements_Envelope11() throws Exception {
        System.out.println("findPossibleChildElements: Envlope 11 (String, String)");
        String namespaceURI = URI_NS_SOAP_1_1;
        String localName = "Envelope";
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SOAP11);
        List<Element> expectedResult;
        expectedResult = (List<Element>) DomUtilities.evaluateXPath(DOC_SOAP11,
          "//*[local-name()='complexType' and @name='Envelope']//*[local-name()='any']");
        expectedResult.addAll((List<Element>) DomUtilities.evaluateXPath(DOC_SOAP11,
          "//*[local-name()='element'][@name='Header' or @name='Body']"));
        List<Element> foundResult = instance.findPossibleChildElements(namespaceURI, localName);
        assertEquals(expectedResult, foundResult);
    }

    @Test
    public void testFindPossibleChildElements_SAML20() throws Exception {
        System.out.println("findPossibleChildElements: SAML 20");
        String namespaceURI = URI_NS_SAML20P;
        String localName = "Response";
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SAML20P);
        instance.appendSchema(DOC_SAML20);
        List<Element> expectedResult;
        expectedResult = (List<Element>) DomUtilities.evaluateXPath(DOC_SAML20,
          "//*[local-name()='element'][@name='Assertion' or @name='EncryptedAssertion']");
        List<Element> foundResult = instance.findPossibleChildElements(namespaceURI, localName);
        assertEquals(expectedResult, foundResult);

    }

    /**
     * Test of findComplexTypeInSchema method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testFindComplexTypeInSchema() throws Exception {
        System.out.println("findComplexTypeInSchema: Response");
        String namespaceURI = URI_NS_SAML20P;
        String elementTypeLocalName = "ResponseType";
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SAML20);
        instance.appendSchema(DOC_SAML20P);
        Element expResult = (Element) DomUtilities.evaluateXPath(DOC_SAML20P,
          "/*[local-name()='schema']/*[local-name()='complexType' and @name='ResponseType']").get(0);
        Element result = instance.findComplexTypeInSchema(namespaceURI, elementTypeLocalName);
        assertEquals(expResult, result);
    }

    /**
     * Test of findElementInSchema method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testFindElementInSchema() throws Exception {
        System.out.println("findElementInSchema: Response");
        String namespaceURI = URI_NS_SAML20P;
        String localName = "Response";
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SAML20);
        instance.appendSchema(DOC_SAML20P);
        assertEquals(2, instance.schemaMap.size());
        assertTrue(instance.schemaMap.containsValue(DOC_SAML20));
        assertTrue(instance.schemaMap.containsKey(URI_NS_SAML20));
        Element expResult = (Element) DomUtilities.evaluateXPath(DOC_SAML20P,
          "/*[local-name()='schema']/*[local-name()='element' and @name='Response']").get(0);
        Element result = instance.findElementInSchema(namespaceURI, localName);
        assertEquals(expResult, result);
    }

    /**
     * Test of dereferenceElement method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testDereferenceElement() throws Exception {
        System.out.println("dereferenceElement");
        Element referringElement = (Element) DomUtilities.evaluateXPath(DOC_SAML20P,
          "//*[local-name()='element' and @ref='saml:Assertion']").get(0);
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SAML20P);
        instance.appendSchema(DOC_SAML20);
        Element expResult = (Element) DomUtilities.evaluateXPath(DOC_SAML20,
          "//*[local-name()='element' and @name='Assertion']").get(0);
        Element result = instance.dereferenceElement(referringElement);
        assertEquals(expResult, result);
    }

    /**
     * Test of findComplexTypeForElement method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testFindComplexTypeForElement() throws Exception {
        System.out.println("findComplexTypeForElement");
        Element elementSchema = (Element) DomUtilities.evaluateXPath(DOC_SAML20P,
          "/*[local-name()='schema']/*[local-name()='element' and @name='Response']").get(0);
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SAML20P);
        Element expResult = (Element) DomUtilities.evaluateXPath(DOC_SAML20P,
          "/*[local-name()='schema']/*[local-name()='complexType' and @name='ResponseType']").get(0);
        Element result = instance.findComplexTypeForElement(elementSchema);
        assertEquals(expResult, result);
    }

    /**
     * Test of getTargetNamespace method, of class SchemaAnalyzerNG.
     */
    @Test
    public void testGetTargetNamespace() throws Exception {
        System.out.println("getTargetNamespace");
        Element x = (Element) DomUtilities.evaluateXPath(DOC_SAML20P,
          "/*[local-name()='schema']/*[local-name()='element' and @name='Response']").get(0);
        SchemaAnalyzerNG instance = new SchemaAnalyzerNG();
        instance.appendSchema(DOC_SAML20P);
        String[] expResult = {PREFIX_NS_SAMLP, URI_NS_SAML20P};
        String[] result = instance.getTargetNamespace(x);
        assertArrayEquals(expResult, result);
    }

    private static Map<String, String> elementToMap(List<Element> elementList) {
        Map<String, String> returnedList = new HashMap<String, String>();
        for (Element ele : elementList) {
            returnedList.put(ele.getNamespaceURI(), ele.getLocalName());
        }
        return returnedList;
    }
}
