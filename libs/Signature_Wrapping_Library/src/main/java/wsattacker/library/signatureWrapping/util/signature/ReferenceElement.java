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
package wsattacker.library.signatureWrapping.util.signature;

import java.util.*;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class ReferenceElement implements ReferringElementInterface {

    private static final String URI_XPATHFILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2";
    private final Element reference;
    private Element referencedElement;
    private Payload payload;
    private final List<XPathElement> xpaths = new ArrayList<XPathElement>();
    private String workingXPath;
    public final static Logger LOG = Logger.getLogger(ReferenceElement.class);

    public ReferenceElement(Element reference) {
        this.reference = reference;
        this.payload = null;
        this.workingXPath = "";

        // get referenced element
        if (getURI().isEmpty()) {
            searchForXPaths(reference);
        } else {
            handleURI(reference);
        }
    }

    public Element getReference() {
        return reference;
    }

    @Override
    public Element getElementNode() {
        return reference;
    }

    public Payload getPayload() {
        return payload;
    }

    public String getURI() {
        return reference.getAttribute("URI");
    }

    public Element getReferencedElement() {
        return referencedElement;
    }

    public List<XPathElement> getXPaths() {
        return xpaths;
    }

    @Override
    public boolean equals(Object o) {
        boolean result = false;
        if (o instanceof ReferenceElement) {
            ReferenceElement ref = (ReferenceElement) o;
            result = ref.getURI().equals(getURI()) && ref.getXPaths().equals(getXPaths());
        }
        return result;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 29 * hash + (getURI() != null ? getURI().hashCode() : 0);
        hash = 29 * hash + (getXPaths() != null ? getXPaths().hashCode() : 0);
        return hash;
    }

    private Logger log() {
        return Logger.getLogger(getClass());
    }

    public String transformIDtoXPath() {
        Attr id = referencedElement.getAttributeNodeNS(NamespaceConstants.URI_NS_WSU, "Id");
        if (id == null) {
            // Workaround if not using wsu:Id
            // E.g. Assertin_ID, or any other kind of ID
            for (int i = 0; i < referencedElement.getAttributes().getLength(); ++i) {
                id = (Attr) referencedElement.getAttributes().item(i);
                if (id.getValue().equals(getURI().substring(1))) {
                    break;
                }
            }
        }
        String name;
        String value;
        if (id.getPrefix() != null) {
            name = id.getPrefix() + ":" + id.getLocalName();
            value = id.getValue();
        } else {
            name = id.getLocalName();
            value = id.getValue();
        }
        return String.format("//*[@%s='%s']", name, value);
    }

    @Override
    public String getXPath() {
        if (workingXPath.isEmpty()) {
            workingXPath = transformIDtoXPath();
        }
        return workingXPath;
    }

    @Override
    public void setXPath(String workingXPath) {
        this.workingXPath = workingXPath;
    }

    @Override
    public String toString() {
        return String.format("URI=\"%s\"", getURI());
    }

    private void searchForXPaths(Element reference) {
        log().trace("URI is empty => Searching XPath Transformations");
        // Searching for XPath Elements
        List<Element> transforms = DomUtilities.findChildren(reference, "Transforms", XMLSignature.XMLNS);
        if (1 == transforms.size()) {
            // we have some transformations
            List<Element> transform = DomUtilities.findChildren(transforms.get(0), "Transform", XMLSignature.XMLNS);
            log().trace(String.format("Found Transforms child element >> %s << whith child elements >> %s <<", transforms, transform));
            for (Element t : transform) {
                if (t.getAttribute("Algorithm").equals(URI_XPATHFILTER2)) {
                    List<Element> xpathElements = DomUtilities.findChildren(t, "XPath", null);
                    log().trace(String.format("Element >> %s << has the XPathFilter2 Algorithm and child elements >> %s <<", t.getNodeName(), xpathElements));
                    for (Element xpath : xpathElements) {
                        this.xpaths.add(new XPathElement(xpath));
                    }
                    break; // No further XPathFilter2 allowed
                } else {
                    log().trace(String.format("Element >> %s << has NO XPathFilter2 Algorithm!", t.getNodeName()));
                }
            }
        } else {
            log().warn(String.format("Found >> %d << Transforms. This is invalid.", transforms.size()));
        }
    }

    private void handleURI(Element reference) throws NullPointerException {
        // URI is not Empty, so no XPaths exist
        String ref = getURI();
        if (ref.charAt(0) == '#') {
            ref = ref.substring(1);
        } // remove #
        List<? extends Node> referenced;
        // First Try: Search for @Id Attribute
        try {
            referenced = (List<Element>) DomUtilities.evaluateXPath(reference.getOwnerDocument(), String.format("//*[@Id='%s']", ref));
        } catch (XPathExpressionException e) {
            referenced = new ArrayList<Element>();
        }
        // Second Try: Search for @wsu:Id Attribute
        if (referenced.isEmpty()) {
            referenced = DomUtilities.findElementByWsuId(reference.getOwnerDocument(), ref);
        }
        // Third Try: Search for any Attribute with specified value
        if (referenced.isEmpty()) {
            referenced = DomUtilities.findAttributeByValue(reference.getOwnerDocument(), ref);
        }

        if (referenced.size() == 1) {
            Node n = referenced.get(0);
            if (n.getNodeType() == Node.ELEMENT_NODE) {
                referencedElement = (Element) referenced.get(0);
            } else if (n.getNodeType() == Node.ATTRIBUTE_NODE) {
                referencedElement = ((Attr) referenced.get(0)).getOwnerElement();
            } else {
                throw new NullPointerException("Don't know how to handle match:" + n.toString() + "(" + n.getClass().getName() + ")");
            }
        } else if (referenced.size() > 1) {
            try {
                List<Attr> attrList = (List<Attr>) referenced;

                LOG.warn("There are " + referenced.size()
                  + " possible References which machtes the URI '"
                  + ref
                  + "' (" + DomUtilities.nodelistToFastXPathList(referenced)
                  + "). This is invalid and must produce errors.");

                // looking for exact matche AssertionID and prefer it
                for (Attr attribute : attrList) {
                    if (attribute.getLocalName().toLowerCase().equals("assertionid")) {
                        referencedElement = attribute.getOwnerElement();
                    }
                }
                // looking for exact matche ID and prefer it
                if (referencedElement == null) {
                    for (Attr attribute : attrList) {
                        if (attribute.getLocalName().toLowerCase().equals("id")) {
                            referencedElement = attribute.getOwnerElement();
                        }
                    }
                }
                // lookiung for substring matching id
                if (referencedElement == null) {
                    for (Attr attribute : attrList) {
                        if (attribute.getLocalName().toLowerCase().contains("id")) {
                            referencedElement = attribute.getOwnerElement();
                        }
                    }
                }
            } catch (ClassCastException e) {
//                reference = (Element) referenced.get(0);
                throw new IllegalStateException("This should never happen", e);
            }

        } else if (referenced.isEmpty()) {
            LOG.warn(String.format("Could not find any References which machtes the URI >> %s <<. No Signed Element found.", ref));
            throw new NullPointerException("Could not de-reference signed element");
        }

        this.payload = new Payload(this, referencedElement);
    }
}
