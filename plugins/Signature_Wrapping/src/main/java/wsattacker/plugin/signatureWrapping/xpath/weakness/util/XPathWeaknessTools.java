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
package wsattacker.plugin.signatureWrapping.xpath.weakness.util;

import java.util.ArrayList;
import java.util.List;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.dom.NamespaceResolver;
import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;

/**
 * Collecion of usefull helper methods for creating XSW messages.
 */
public class XPathWeaknessTools
{
  private static Logger log = Logger.getLogger(XPathWeaknessTools.class);

  /**
   * Returns a clone of the signedPostPart Element but instead of the
   * decendant-or-self signedElement, the payloadElement is placed.
   * @param signedPostPart is an ancestor-or-self of signedElement
   * @param signedElement is a decendant-or-self of signedPostPart
   * @param payloadElement
   * @return
   */
  public static Element createPayloadPostPart(Element signedPostPart,
                                              Element signedElement,
                                              Element payloadElement)
  {

    // special case = signedElement = signedPostPart
    if (signedElement == signedPostPart)
    {
      return payloadElement;
    }

    // 1) Get "fast xpath position" of the signed Element beginning at signedPostPart
    List<Element> parentElements = new ArrayList<Element>();
    List<Integer> parentIndex = new ArrayList<Integer>();
    // First: Add each parent node to a temporary list
    // (Go upstairs to signedPostPart beginning with element)
    Node theParent = signedElement;
    while (theParent != null && theParent.getNodeType() == Node.ELEMENT_NODE && theParent != signedPostPart)
    {
      parentElements.add((Element) theParent);
      parentIndex.add(DomUtilities.getElementIndex((Element) theParent));
      theParent = theParent.getParentNode();
    }

    // 2) Clone the signedPostPart
    Element payloadPostPart = (Element) signedPostPart.cloneNode(true);

    // 3) Detect signedElement in clone via "fast xpath" method
    Element tmp = payloadPostPart;
    for (int i = parentElements.size() - 1; i >= 0; --i)
    {
      Element child = parentElements.get(i);
      int index = parentIndex.get(i);
//      NodeList children = tmp.getElementsByTagNameNS(child.getNamespaceURI(), child.getLocalName());
//      tmp = (Element) children.item(index - 1); // Index of Node is 1 based, lists start with element 0
      List<Element> children = DomUtilities.findChildren(tmp, child.getLocalName(), child.getNamespaceURI());
      tmp = children.get(index - 1);
    }

    // 4) Append payloadElement and remove signedElementCopy=tmp
    tmp.getParentNode().replaceChild(payloadElement, tmp);

    return payloadPostPart;
  }

  /**
   * Detects the minimal Elements protected by the postXPath.
   * Therefore, the postXPath is evaluated from the signedElement
   * and step by step by its parents until the postXPath
   * matches exactly one Element. This one is returned.
   * @param signedElement
   * @param postXPath
   * @return
   */
  public static Element detectHashedPostTree(Element signedElement,
                                             String postXPath)
  {
    Element signedPostPart = signedElement;
    Node signedPostPartParent = (Element) signedPostPart.getParentNode();
    XPathFactory factory = XPathFactory.newInstance();
    XPath xpath = factory.newXPath();
    xpath.setNamespaceContext(new NamespaceResolver(signedElement.getOwnerDocument()));
    XPathExpression expr = null;
    try
    {
      expr = xpath.compile(postXPath);
    }
    catch (XPathExpressionException e1)
    {
      log.warn("No valid PostXPath: " + postXPath);
      return null;
    }
    NodeList nodes;
    while (signedPostPartParent != null && signedPostPartParent.getNodeType() == Node.ELEMENT_NODE)
    {
      try
      {
        nodes = (NodeList) expr.evaluate(signedPostPartParent, XPathConstants.NODESET);
      }
      catch (XPathExpressionException e)
      {
        continue;
      }
      if (nodes.getLength() == 1)
      {
        if (log.isDebugEnabled()) {
			log.debug("Matched with postXPath from Element: " + signedPostPart.getNodeName());
		}
        break;
      }
      signedPostPart = (Element) signedPostPartParent;
      signedPostPartParent = signedPostPart.getParentNode();
    }
    return signedPostPart;
  }
  
  /**
   * Evaluates the XPaths up to the Step step and returns a List of Elements
   * which contain the signedElement as a descendant-or-self.
   * @param step
   * @param signedElement
   * @return
   * @throws InvalidWeaknessException
   */
  public static List<Element> getSignedPostPart(Step step, Element signedElement) throws InvalidWeaknessException {

    // get extended PreXPath
    String xpath = step.getPreXPath() + "/" + step.getStep();
    List<Element> matchList;
    try
   {
     matchList = DomUtilities.evaluateXPath(signedElement.getOwnerDocument(), xpath);
   }
   catch (XPathExpressionException e)
   {
     e.printStackTrace();
     log.warn(e.getLocalizedMessage());
     throw new InvalidWeaknessException(e);
   }
   if (matchList.isEmpty())
   {
     throw new InvalidWeaknessException("XPath does not match any Element");  
   }
   List<Element> haveSignedDecendant = new ArrayList<Element>();
   for(Element match : matchList) {
		if ( isAncestorOf(match, signedElement) >= 0) {
				haveSignedDecendant.add(match);
		}
   }
   return haveSignedDecendant;
  }

  /**
   * Checks if ancestor-Element is an ancestor of maybeChild Element
   * 
   * @param the
   *          ancestor-Element
   * @param the
   *          maybeChild-Element
   * @return -1 if not an ancestor, 0 if ancestor==maybeChild, otherwise the number of Elements to go up from maybeChild
   *         to reach the ancestor.
   */
  public static int isAncestorOf(Element ancestor,
                                 Element maybeChild)
  {
    if (ancestor == maybeChild) {
		return 0;
	}
    Node parent = maybeChild.getParentNode();

    int i = 1;
    while (parent != null && parent != ancestor)
    {
      parent = parent.getParentNode();
      ++i;
    }

    if (parent == ancestor) {
		return i;
	}
    return -1;
  }
}
