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
package wsattacker.plugin.signatureWrapping.schema;

import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.*;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Level;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.dom.NamespaceResolver;
import wsattacker.util.SortedUniqueList;

public class SchemaAnalyzer implements SchemaAnalyzerInterface
{

  private static Logger log = Logger.getLogger(SchemaAnalyzer.class);

  Document              schema, analyzingDocument, expandedAnalyzingDocument;
  List<QName>           filterList;

  public SchemaAnalyzer()
  {
    clearSchemas();
    analyzingDocument = null;
    expandedAnalyzingDocument = null;
    filterList = new ArrayList<QName>();
  }

  public Document getSchema()
  {
    return schema;
  }

  public Document getExpandedAnalyzingDocument()
  {
    return expandedAnalyzingDocument;
  }

  public Document getAnalyzingDocument()
  {
    return analyzingDocument;
  }

  public List<QName> getFilterList()
  {
    return filterList;
  }

  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.SchemaAnalyserInterface#setFilterList(java.util.List)
   */
  @Override
  public void setFilterList(List<QName> filterList)
  {
    this.filterList = filterList;
  }

  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.SchemaAnalyserInterface#appendSchema(org.w3c.dom.Document)
   */
  @Override
  public void appendSchema(Document newSchema)
  {
    Element newSchemaRoot = newSchema.getDocumentElement();
    // Only Append if Document is a Schema Document
    if (newSchema != null && URI_NS_SCHEMA.equals(newSchemaRoot.getNamespaceURI()) && "schema".equals(newSchemaRoot
        .getLocalName()))
    {
      Node importedRoot = schema.importNode(newSchemaRoot, true);
      schema.getDocumentElement().appendChild(importedRoot);
    }
    new NamespaceResolver(schema);
  }

  public void clearSchemas()
  {
    schema = DomUtilities.createDomDocument();
    Element root = schema.createElement("allSchemas");
    schema.appendChild(root);
  }

  public boolean isInCurrentAnalysis(Node n)
  {
    boolean result = (analyzingDocument != null && (n.getOwnerDocument().getDocumentElement()
        .isEqualNode(analyzingDocument.getDocumentElement())));
// boolean result = (analyzingDocument != null &&
// (DomUtilities.domToString(analyzingDocument).equals(DomUtilities.domToString(n.getOwnerDocument()))));
    log.trace(String.format("isInCurrent: %b", result));
    return result;
  }

  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.SchemaAnalyserInterface#findExpansionPoint(org.w3c.dom.Element)
   */
  @Override
  public List<AnyElementPropertiesInterface> findExpansionPoint(Element fromHere)
  {
    if (!isInCurrentAnalysis(fromHere))
    {
      log.trace("New Document to analyze!");
      // We will clone the Document of Node fromHere and add all possible expansionpoints
      expandedAnalyzingDocument = DomUtilities.createNewDomFromNode(fromHere.getOwnerDocument().getDocumentElement());
      analyzingDocument = fromHere.getOwnerDocument();
    }
    Document expandedDoc = expandedAnalyzingDocument; // get current analyzed document
    Element start = DomUtilities.findCorrespondingElement(expandedDoc, fromHere); // corresponding "fromHere"
    // return a Map of <Node,Properties>
    List<AnyElementPropertiesInterface> result = new SortedUniqueList<AnyElementPropertiesInterface>();
    findExpansionPoint(result, start);
    return result;
  }

  private void findExpansionPoint(List<AnyElementPropertiesInterface> result,
                                  Element start)
  {
    log.setLevel(Level.TRACE);
    log.trace("Find expansion point of Element '" + start.getNodeName() + "'");
    // Shall the Element be filtered?
    if (filterList.contains(new QName(start.getNamespaceURI(), start.getLocalName())))
    {
      log.trace("\tFound in filterList -> Abort");
      return;
    }
    // Find allowed child elements of start element
    Element complexType = findComplexType(start.getLocalName(), start.getNamespaceURI());
    if (complexType == null)
    {
      log.trace("\tNo ComplexType can be found.. maybe simple type -> Aborting");
      return;
    }
    List<Element> allowedChildElements = DomUtilities.findChildren(complexType, "element", URI_NS_SCHEMA, true);
    // For each allowed child element
    for (Element ele : allowedChildElements)
    {
      // Get Element Localname
      String localName = ele.getAttribute("ref").substring(1 + ele.getAttribute("ref").indexOf(':'));
      if (localName.isEmpty()) {
		    continue;
	    }
      log.trace("\tAllowed Child: '" + localName + "'");
      // Check if Element exists
      if (  DomUtilities.findChildren(start, localName, start.getNamespaceURI(), false).isEmpty())
      {
        
        // Check if an identical ancestor element exists:
        boolean contained = false;
        Node up = start.getParentNode();

        while (up != null && up.getNodeType() == Node.ELEMENT_NODE)
        {
          if (up.getNamespaceURI().equals(start.getNamespaceURI()) && up.getLocalName().equals(start.getLocalName())) {
            contained = true;
            break;
          }
          up = up.getParentNode();
        }
        
        // Create if not
        if (contained) {
          log.trace("\t\tAncestor with same name already exists -> *NOT* Created");
        }
        else {
          start.appendChild(start.getOwnerDocument()
            .createElementNS(start.getNamespaceURI(), start.getPrefix() + ":" + localName));
          log.trace("\t\tDoes not exist -> Created");
        }
      }
    }
    // Check if any of them is xs:any
    List<Element> anyChilds = DomUtilities.findChildren(complexType, "any", URI_NS_SCHEMA, true);
    // If true
    if (anyChilds.size() > 0)
    {
      // get its properties
      // and add the element to return list
      result.add(new AnyElementProperties(anyChilds.get(0), start));
      log.trace("\t-> xs:any <- allowed!");
    }
    // Recursive with all child elements
    NodeList theChildren = start.getChildNodes();
    for (int i = 0; i < theChildren.getLength(); ++i) {
		  if (theChildren.item(i).getNodeType() == Node.ELEMENT_NODE) {
		    findExpansionPoint(result, (Element) theChildren.item(i));
	    }
	  }

  }

  /**
   * Returns a List of al xs:any Elements in all known Schema files.
   * 
   * @return
   */
  public List<Element> getXsAny()
  {
    // TODO: Needless, can be removed.
    List<Element> xsAny;
    try
    {
      xsAny = DomUtilities
          .evaluateXPath(getSchema(), "//*[local-name()=\"any\" and namespace-uri()=\"" + URI_NS_SCHEMA + "\"]");
    }
    catch (XPathExpressionException e)
    {
      e.printStackTrace();
      xsAny = new ArrayList<Element>();
    }
    return xsAny;
  }

  /**
   * Returns the Schemas Complex Type of the xs:any up node E.g. xs:any -> soap:Header of the xs:any in the Header.
   * 
   * @param xsAny
   * @return
   */
  public Element getXsAnyComplexType(Element xsAny)
  {
    // TODO: Needless, can be removed.
    Node parent = xsAny;
    do
    {
      parent = parent.getParentNode();
    }
    while (parent != null && !("complexType".equals(parent.getLocalName()) && URI_NS_SCHEMA.equals(parent
        .getNamespaceURI())));
    if (parent instanceof Element) {
		  return (Element) parent;
	  }
    return null;
  }

  /**
   * Returns a StringPair of the targetNamespace of an Schema-Element.
   * 
   * @param x
   *          Schema Element
   * @return String[2] with {prefix,targetNS}
   */
  public String[] getTargetNamespace(Element x)
  {
    Node parent = x;
    do
    {
      parent = parent.getParentNode();
      if (parent != null && "schema".equals(parent.getLocalName()) && URI_NS_SCHEMA.equals(parent.getNamespaceURI())) {
		    break;
	    }
    }
    while (parent != null);
    Element p;
    if (parent instanceof Element) {
		  p = (Element) parent;
	  }
    else {
		  return new String[]
		  { "", "" };
	  }
    String targetNS = p.getAttribute("targetNamespace");
    String prefix = "";
    if (targetNS.isEmpty()) {
		  return new String[]
		  { prefix, targetNS };
	  }
    NamedNodeMap attributes = parent.getAttributes();
    for (int i = 0; i < attributes.getLength(); ++i)
    {
      Node attribute = attributes.item(i);
      if (attribute.getPrefix() != null && attribute.getPrefix().equals("xmlns") && attribute.getTextContent()
          .equals(targetNS))
      {
        prefix = attribute.getLocalName();
        break;
      }
    }
    return new String[]
    { prefix, targetNS };
  }

  /**
   * Schema Parser: ComplexType -> Schema-Element
   * 
   * @param xsAnyComplexType
   * @return
   */
  public Element getXsAnyElement(Element xsAnyComplexType)
  {
    // TODO: Needless, can be removed.
    List<Element> types;
    Element parent = (Element) xsAnyComplexType.getParentNode();
    // Case: Element = Parent
    if ("element".equals(parent.getLocalName()) && URI_NS_SCHEMA.equals(parent.getNamespaceURI())) {
		  return parent;
	  }
    // Case: Element is referenced
    String[] ns = getTargetNamespace(xsAnyComplexType);
    String prefix = "";
    if (!ns[0].isEmpty()) {
		  prefix = ns[0] + ":";
	  }

    try
    {
      types = DomUtilities
          .evaluateXPath(schema, "//*[local-name()=\"element\" and namespace-uri()=\"" + URI_NS_SCHEMA + "\" and @type=\"" + prefix + xsAnyComplexType
              .getAttribute("name") + "\"]");
    }
    catch (XPathExpressionException e)
    {
      e.printStackTrace();
      return null;
    }
    if (types.size() != 1) {
		  System.err.println("### Error: Found " + types.size() + " Matches for Name='" + xsAnyComplexType
		      .getAttribute("name") + "'");
	  }
    return types.get(0);
  }

  /**
   * Schema Parser: Schema-Element -> Parent Elements
   * 
   * @param xsElement
   * @return
   */
  public List<Element> findParents(Element xsElement)
  {
    // TODO: Needless, can be removed.
    String elementName = xsElement.getAttribute("name");
    String[] ns = getTargetNamespace(xsElement);
    String prefix = "";
    if (!ns[0].isEmpty()) {
		  prefix = ns[0] + ":";
	  }
    List<Element> parents;
    try
    {
      parents = DomUtilities
          .evaluateXPath(schema, "//*[local-name()=\"element\" and namespace-uri()=\"" + URI_NS_SCHEMA + "\" and @ref=\"" + prefix + elementName + "\"]");
    }
    catch (XPathExpressionException e)
    {
      return new ArrayList<Element>();
    }
    return parents;
  }

  public Element findComplexType(String name,
                                 String namespaceURI)
  {
    String xpath;
    xpath = "//*[local-name()='schema' and namespace-uri()='" + URI_NS_SCHEMA + "' and @targetNamespace='" + namespaceURI + "']//*[local-name()='element' and namespace-uri()='" + URI_NS_SCHEMA + "' and @name='" + name + "']";
// System.out.println("XPATH to Eval:\n"+xpath+"\n");
    List<Element> match;
    try
    {
      match = DomUtilities.evaluateXPath(schema, xpath);
    }
    catch (XPathExpressionException e)
    {
      e.printStackTrace();
      return null;
    }
    // Nothing found, abort
    if (match.size() == 0) {
		  return null;
	  }
    // Should be unique
    String complexType = match.get(0).getAttribute("type");

    // Find ComplexType Element
    xpath = "//*[local-name()='schema' and namespace-uri()='" + URI_NS_SCHEMA + "' and @targetNamespace='" + namespaceURI + "']//*[local-name()='complexType' and namespace-uri()='" + URI_NS_SCHEMA + "' and @name='" + complexType
        .substring(complexType.indexOf(":") + 1) + "']";
// System.out.println("XPATH to Eval:\n"+xpath+"\n");
    try
    {
      match = DomUtilities.evaluateXPath(schema, xpath);
    }
    catch (XPathExpressionException e)
    {
      e.printStackTrace();
      return null;
    }
    // Nothing found, abort
    if (match.size() == 0) {
		  return null;
	  }
    return match.get(0);
  }
}
