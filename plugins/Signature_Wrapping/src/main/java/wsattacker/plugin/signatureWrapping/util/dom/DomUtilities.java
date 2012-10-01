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
package wsattacker.plugin.signatureWrapping.util.dom;

import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_WSU;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class DomUtilities
{

  private static Logger log = Logger.getLogger(DomUtilities.class);

  /**
   * Returns a valid FastXPath that would match the given Node in its Document.
   * 
   * @param node
   * @return FastXPath String
   */
  public static String getFastXPath(Node node)
  {
    StringBuffer buf = new StringBuffer();
    Element ele;
    switch (node.getNodeType())
    {
      case Node.ELEMENT_NODE:
        ele = (Element) node;
        break;
      case Node.TEXT_NODE:
        buf.append("/text()");
        ele = (Element) node.getParentNode();
        break;
      default:
        return "###ERROR###";
    }
    int index = getElementIndex(ele);
    buf.append(ele.getNodeName() + "[" + index + "]");
    Node parent = ele.getParentNode();
// while (parent != ele.getOwnerDocument())
    while (parent != null && parent.getNodeType() == Node.ELEMENT_NODE)
    {
      index = getElementIndex((Element) parent);
      buf.insert(0, parent.getNodeName() + "[" + index + "]/");
      parent = parent.getParentNode();
    }
    buf.insert(0, "/");
    return buf.toString();
  }

  /**
   * Returns the index of the Node within the current sub-tree. Mainly used for creating FastXPath expressions (
   * {@link #getFastXPath(Node)})
   * 
   * @param ele
   * @return
   */
  public static int getElementIndex(Element ele)
  {
    int index = 1;
    Node prev = ele.getPreviousSibling();
    while (prev != null)
    {
      if (prev.getNodeType() == Node.ELEMENT_NODE)
      {
        if (((Element) prev).getNodeName().equals(ele.getNodeName())) {
		      ++index;
	      }
      }
      prev = prev.getPreviousSibling();
    }
    return index;
  }

  /**
   * Transforms a List<Node> to a List<String>. Each String in the List is a FastXPath that matches the corresponding
   * Node ( {@link #getFastXPath(Node)}.
   * 
   * @param nodelist
   * @return
   */
  public static List<String> nodelistToFastXPathList(List<? extends Node> nodelist)
  {
    List<String> fastXPathList = new ArrayList<String>();
    for (Node n : nodelist)
      fastXPathList.add(getFastXPath(n));
    return fastXPathList;
  }

  /**
   * Takes a Document and evaluates an XPath expression on it. All matching Nodes are returned as a List.
   * 
   * @param doc
   *          The Document.
   * @param path
   *          The XPath expression.
   * @return List<Node> that match the XPath.
   * @throws XPathExpressionException
   */
  public static List<Element> evaluateXPath(Document doc,
                                            String path)
                                                        throws XPathExpressionException
  {
    XPathFactory factory = XPathFactory.newInstance();
    XPath xpath = factory.newXPath();
    xpath.setNamespaceContext(new NamespaceResolver(doc));
    XPathExpression expr = xpath.compile(path);
    NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
    List<Element> nodelist = new ArrayList<Element>();
    for (int i = 0; i < nodes.getLength(); ++i)
      if (nodes.item(i).getNodeType() == Node.ELEMENT_NODE)
        nodelist.add((Element) nodes.item(i));
      else
        Logger.getLogger(DomUtilities.class).warn("Found Node : " + nodes.item(i).getNodeName() + " = " + nodes.item(i)
            .getNodeValue() + " with XPATH " + path);
    log.trace("Evaluated XPATH: " + path + " and found " + nodeListToString(nodelist));
    return nodelist;
  }

  /**
   * Finds an Element by its ID name. Looks for wsu:Id.
   * 
   * @param doc
   * @param id
   *          : ID to search. Does not start with a Hash (#) Sign.
   * @return
   */
  public static List<Element> findElementByWsuId(Document doc,
                                                 String id)
  {
// String xpath = "//*[@wsu:Id='"+id+"']"; // very basic
// String xpath = "//*[attribute::wsu:Id='"+id+"']"; // expanded from basic
    String xpath = "//attribute::*[local-name()='Id' and namespace-uri()='" + URI_NS_WSU + "' and string()='" + id + "']/parent::node()"; // independent
// from prefix
    try
    {
      List<Element> result = evaluateXPath(doc, xpath);
      log.trace("### WSU IDs found ### \n" + nodelistToFastXPathList(result));
      return result;
    }
    catch (XPathExpressionException e)
    {
      System.out.println("BAD XPATH: " + xpath);
      return new ArrayList<Element>();
    }
  }
  
    /**
   * Finds an Element by its ID name. Looks for wsu:Id.
   * 
   * @param doc
   * @param attributeValue
   *          : ID to search. Does not start with a Hash (#) Sign.
   * @return
   */
  public static List<Element> findElementByAttributeValue(Document doc,
                                                 String attributeValue)
  {
    List<Element> returnedElements = new ArrayList<Element>();
    String xpath = "//attribute::*[string()='" + attributeValue + "']/parent::node()";
    try
    {
      returnedElements = evaluateXPath(doc, xpath);
      log.trace("### Element with Attribute '"+attributeValue+"' ### \n" + nodelistToFastXPathList(returnedElements));

    }
    catch (XPathExpressionException e)
    {
      System.out.println("BAD XPATH: " + xpath);
    }
    return returnedElements;
  }
  
  

  /**
   * Returns the first child Element of a given Node.
   * 
   * @param node
   * @return Child Element.
   */
  public static Element getFirstChildElement(Node node)
  {
    Node child = node.getFirstChild();
    while ((child != null) && (child.getNodeType() != Node.ELEMENT_NODE))
    {
      child = child.getNextSibling();
    }
    return (Element) child;
  }

  /**
   * Returns the next sibling element of a Node.
   * 
   * @param node
   * @return Next Sibling
   */
  public static Element getNextSiblingElement(Node node)
  {
    Node sibling = node.getNextSibling();
    while ((sibling != null) && (sibling.getNodeType() != Node.ELEMENT_NODE))
    {
      sibling = sibling.getNextSibling();
    }
    return (Element) sibling;
  }

  /**
   * Finds child elements that matches a given prefix:localname.
   * 
   * @param parent
   *          The parent Node
   * @param localname
   *          Localename of the child, null for matching every child
   * @param namespaceuri
   *          Namespace-URI of the child, null for matching every namespace
   * @return List<Element>
   */
  public static List<Element> findChildren(Node parent,
                                           String localname,
                                           String namespaceuri)
  {
    return findChildren(parent, localname, namespaceuri, false);
  }

  /**
   * Finds child elements that matches a given prefix:localname.
   * 
   * @param parent
   *          The parent Node
   * @param localname
   *          Localename of the child, null for matching every child
   * @param namespaceuri
   *          Namespace-URI of the child, null for matching very namespace
   * @param deep
   *          if true, the search will be recursive with child elements
   * @return List<Element>
   */
  public static List<Element> findChildren(Node parent,
                                           String localname,
                                           String namespaceuri,
                                           boolean deep)
  {
    List<Element> matches = new ArrayList<Element>();
    findChildren(matches, parent, localname, namespaceuri, deep);
    return matches;
  }

  private static void findChildren(List<Element> result,
                                   Node parent,
                                   String localname,
                                   String namespaceuri,
                                   boolean deep)
  {
    log.trace("From " + parent.getNodeName() + " find children " + localname + " with URI " + namespaceuri + (deep ? " DEEP" : " nondeep"));
    NodeList children = parent.getChildNodes();
    for (int i = 0; i < children.getLength(); ++i)
    {
      Node n = children.item(i);
      log.trace("Found Child: " + children.item(i).getNodeName());
      if (n != null && n.getNodeType() == Node.ELEMENT_NODE) {
		    if (localname == null || n.getLocalName().equals(localname)) {
		      if (namespaceuri == null || n.getNamespaceURI().equals(namespaceuri)) {
				    result.add((Element) n);
			    }
	      }
	    }
      if (deep) {
		    findChildren(result, n, localname, namespaceuri, deep);
	    }
    }
  }

  /**
   * Get all child elements of Element ele as a List of Elements. Non recursive.
   * 
   * @param ele
   * @return
   */
  public static List<Element> getAllChildElements(Element ele)
  {
    return getAllChildElements(ele, false);
  }

  /**
   * Get all child elements of Element ele as a List of Elements. If recursive is true, even the child elements of all
   * childelements are fetched recursively.
   * 
   * @param ele
   * @param recursive
   * @return
   */
  public static List<Element> getAllChildElements(Element ele,
                                                  boolean recursive)
  {
    List<Element> list = new ArrayList<Element>();
    return getAllChildElements(ele, recursive, list);
  }

  private static List<Element> getAllChildElements(Element ele,
                                                   boolean recursive,
                                                   List<Element> list)
  {
    NodeList nl = ele.getChildNodes();
    for (int i = 0; i < nl.getLength(); ++i)
    {
      Node n = nl.item(i);
      if (n.getNodeType() != Node.ELEMENT_NODE) {
		    continue;
	    }
      list.add((Element) n);
      if (recursive) {
		    getAllChildElements((Element) n, recursive, list);
	    }
    }
    return list;
  }

  /**
   * Creates an empty Document
   * 
   * @return
   */
  public static Document createDomDocument()
  {
    try
    {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.newDocument();
      return doc;
    }
    catch (ParserConfigurationException e)
    {
    }
    return null;
  }

  /**
   * Creates a new Docume1nt with the Node toClone as root Element Can be used to clone a Document with
   * createNewDomFromNode(rootToClone)
   * 
   * @param toClone
   * @return
   */
  public static Document createNewDomFromNode(Node toClone)
  {
    Document newDoc = createDomDocument(); // empty Doc
    Node importedNode = newDoc.importNode(toClone, true); // import node to clone, deep copy
    newDoc.appendChild(importedNode); // the clone
    return newDoc;
  }

  // *****************************************************************
  // Read / Write XML
  // *****************************************************************
  public static Document readDocument(String filename)
                                                      throws FileNotFoundException,
                                                        SAXException,
                                                        IOException
  {
    File file = new File(filename);
    return readDocument(file);
  }

  public static Document readDocument(File file)
                                                throws FileNotFoundException,
                                                  SAXException,
                                                  IOException
  {
    return readDocument(new FileInputStream(file));
  }

  public static Document readDocument(URL url)
                                              throws SAXException,
                                                IOException
  {
    URLConnection con = url.openConnection();
    con.setConnectTimeout(1000);
    con.setReadTimeout(1000);
    con.setUseCaches(true);
    return readDocument(url.openStream());
  }

  /**
   * Reads an XML file and returns a Document.
   * 
   * @param file
   * @return Document
   * @throws ParserConfigurationException
   * @throws FileNotFoundException
   * @throws SAXException
   * @throws IOException
   */

  public static Document readDocument(InputStream is)
                                                     throws SAXException,
                                                       IOException
  {
    DocumentBuilderFactory fac = DocumentBuilderFactory.newInstance();
    fac.setNamespaceAware(true);
    // fac.setIgnoringElementContentWhitespace(true);
    DocumentBuilder builder = null;
    try
    {
      builder = fac.newDocumentBuilder();
    }
    catch (ParserConfigurationException e)
    {
      // can never happen
    }
    return builder.parse(is);
  }

  /**
   * Writes a Document to a file.
   * 
   * @param doc
   * @param filename
   */

  public static void writeDocument(Document doc,
                                   String filename)
  {
    writeDocument(doc, filename, false);
  }

  public static void writeDocument(Document doc,
                                   String filename,
                                   boolean prettyPrint)
  {
    try
    {
      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer trans = tf.newTransformer();
      if (prettyPrint)
      {
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
      }
      trans.transform(new DOMSource(doc), new StreamResult(new FileOutputStream(filename)));
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }

  // *****************************************************************
  // String/DOM Conversation
  // *****************************************************************

  /**
   * Converts a String to a Document. Namespace awareness is on.
   * 
   * @param xmlString
   * @return
   * @throws SAXException
   */
  public static Document stringToDom(String xmlString)
                                                      throws SAXException
  {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    StringReader reader = new StringReader(xmlString);
    InputSource input = new InputSource(reader);
    DocumentBuilder builder = null;
    try
    {
      builder = factory.newDocumentBuilder();
    }
    catch (ParserConfigurationException e)
    {
      // will never happen
    }
    Document dom = null;
    try
    {
      dom = builder.parse(input);
    }
    catch (IOException e)
    {
      // will never happen
      dom = DomUtilities.createDomDocument();
    }
    return dom;
  }

  /**
   * Converts a DOM to a String
   * 
   * @param domDoc
   * @return
   */
  public static String domToString(Document domDoc)
  {
    return domToString(domDoc.getDocumentElement(), false);
  }

  public static String domToString(Document domDoc,
                                   boolean prettyPrint)
  {
    return domToString(domDoc.getDocumentElement(), prettyPrint);
  }

  /**
   * Converts a DOM Node to a String
   * 
   * @param Node
   *          n
   * @return
   */
  public static String domToString(Node n)
  {
    return domToString(n, false);
  }

  public static String domToString(Node n,
                                   boolean prettyPrint)
  {
    StringWriter output = new StringWriter();
    Transformer transformer = null;
    try
    {
      transformer = TransformerFactory.newInstance().newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      if (prettyPrint)
      {
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
      }
      transformer.transform(new DOMSource(n), new StreamResult(output));
    }
    catch (Exception e)
    {
      // will never happen;
    }
    return output.toString();
  }

  public static String showOnlyImportant(Document doc)
  {
    return showOnlyImportant(doc.getDocumentElement());
  }

  public static String showOnlyImportant(Node node)
  {
    return showOnlyImportant(domToString(node, true));
  }

  public static String showOnlyImportant(String xml)
  {
    // Filter out specific elements
    String[] tasks =
      {
          "ds:KeyInfo", "ds:SignatureValue", "ds:SignedInfo"
      };
    for (String task : tasks)
    {
// xml = xml.replaceAll("<" + task + "(.|\\n)*<\\/" + task + ">", "<" + task + "/>");
      for (int start = xml.indexOf("<" + task); start >= 0; start = xml.indexOf("<" + task))
      {
        String endString = "/" + task + ">";
        int end = xml.indexOf(endString, start+1);
        if (end > 0)
          xml = xml.substring(0, start) + "<" + task + "/>" + xml.substring(end + endString.length());
        else
          break;
      }
    }
    // Filter out namespace declarations
// xml = xml.replaceAll("\\sxmlns:\\S+['\"]", "");
    String nsOpen = " xmlns:";
    for (int start = xml.indexOf(nsOpen); start >= 0; start = xml.indexOf(nsOpen))
    {
      int nextWhitespace = xml.indexOf(' ', start + 1);
      int nextClose = xml.indexOf('>', start + 1);
      if (nextClose < nextWhitespace && nextClose >= 0)
      {
        xml = xml.substring(0, start) + xml.substring(nextClose);
      }
      else if (nextWhitespace >= 0)
      {
        xml = xml.substring(0, start) + xml.substring(nextWhitespace);
      }
      else
        break;
    }
    return xml;
  }

  /***
   * PrettyPrints a List<Node>
   * 
   * @param list
   * @return
   */
  public static String nodeListToString(List<? extends Node> list)
  {
    StringBuffer buf = new StringBuffer();
    buf.append("{");
    if (list.size() > 0)
    {
      buf.append("\n  0 : [" + domToString(list.get(0)) + "]");
      for (int i = 1; i < list.size(); ++i)
        buf.append("\n  " + i + " : [" + domToString(list.get(0)) + "]");
      buf.append("\n");
    }
    buf.append("}");
    return buf.toString();
  }

  /**
     * The Element element is not part of the Document doc. This Function returns the corresponding Element in doc. If it
     * does not exist yet, it will be created.
     * 
     * @param doc
     * @param element
     * @return
     */
    public static Element findCorrespondingElement(Document doc,
                                                   Element element)
    {
      List<Element> parentElements = new ArrayList<Element>();
      List<Integer> parentIndex = new ArrayList<Integer>();
      // First: Add each parent node to a temporary list
      // (Go upstairs to root beginning with element)
      Node theParent = element;
      while (theParent != null && theParent.getNodeType() == Node.ELEMENT_NODE)
      {
        parentElements.add((Element) theParent);
        parentIndex.add(getElementIndex((Element) theParent));
        theParent = theParent.getParentNode();
      }
      // Second: Travel the list of parents in reverse order
      // (Go downstairs from root to the corresponding element)
      Element ret = doc.getDocumentElement();
      if (ret.isSameNode(element.getOwnerDocument().getDocumentElement())) {
		    System.err.println("No different Root Nodes");
	    }
      for (int i = (parentElements.size() - 2); i >= 0; --i) // -2 as root should be the same
      {
        Element child = parentElements.get(i);
        int index = parentIndex.get(i);
  //      NodeList children = ret.getElementsByTagNameNS(child.getNamespaceURI(), child.getLocalName()); // Bad: This is recursive
        List<Element> children = findChildren(ret, child.getLocalName(), child.getNamespaceURI()); // Non-Recursive
        if (index > children.size())
        {
          // create nodes if not exist
          for (int j = 0; j < (index - children.size()); ++j)
          {
            Node imported = doc.importNode(child, false);
            ret.appendChild(imported);
          }
          // re-get children
  //        children = ret.getElementsByTagNameNS(child.getNamespaceURI(), child.getLocalName());
          children = findChildren(ret, child.getLocalName(), child.getNamespaceURI());
        }
        // ret = (Element) children.item(index - 1); // Index of Node is 1 based, lists start with element 0
        ret = children.get(index - 1); // Index of Node is 1 based, lists start with element 0
      }
      return ret;
    }
}
