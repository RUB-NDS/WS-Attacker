package wsattacker.plugin.signatureWrapping.util.signature;

import java.util.*;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.xpath.XPathExpressionException;

import org.apache.log4j.Logger;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

public class ReferenceElement implements ReferringElementInterface
{

  private static String      uriXPATHFILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2";

  private Element            reference, referencedElement;
  private OptionPayload      payload;
  private List<XPathElement> xpaths;
  private String             workingXPath;

  public static Logger       log             = Logger.getLogger(ReferenceElement.class);

  public ReferenceElement(Element reference)
  {
    this.reference = reference;
    this.payload = null;
    this.workingXPath = "";

    // get referenced element

    if (getURI().isEmpty())
    {
      log().trace("URI is empty => Searching XPath Transformations");
      // Searching for XPath Elements
      xpaths = new ArrayList<XPathElement>();
      List<Element> transforms = DomUtilities.findChildren(reference, "Transforms", XMLSignature.XMLNS);
      if (1 == transforms.size())
      {
        // we have some transformations
        List<Element> transform = DomUtilities.findChildren(transforms.get(0), "Transform", XMLSignature.XMLNS);
        log().trace("Found Transforms child element: " + transforms + " whith child elements: " + transform);
        for (Element t : transform)
        {
          if (t.getAttribute("Algorithm").equals(uriXPATHFILTER2))
          {
            List<Element> xpaths = DomUtilities.findChildren(t, "XPath", null);
            log().trace("Element " + t.getNodeName() + " has the XPathFilter2 Algorithm and child elements: " + xpaths);
            for (Element xpath : xpaths)
            {
              this.xpaths.add(new XPathElement(xpath));
            }
            break; // No further XPathFilter2 allowed
          }
          else
            log().trace("Element + " + t.getNodeName() + " has NO XPathFilter2 Algorithm!");
        }
      }
      else
      {
        log().warn("Found " + transforms.size() + " Transforms. This is invalid.");
      }
    }
    else
    {
      // URI is not Empty, so no XPaths exist

      String ref = getURI();
      if (ref.startsWith("#"))
        ref = ref.substring(1); // remove #
      List<Element> referenced;
      try
      {
        referenced = DomUtilities.evaluateXPath(reference.getOwnerDocument(), "//*[@Id='" + ref + "']");
      }
      catch (XPathExpressionException e)
      {
        referenced = new ArrayList<Element>();
      }
      if (referenced.isEmpty())
      {
        referenced = DomUtilities.findElementByWsuId(reference.getOwnerDocument(), ref);
      }
      if (referenced.size() != 1)
        log.warn("There are " + referenced.size() + " possible References which macht the URI '" + ref + "'. This is invalid and must produce errors.");
      referencedElement = referenced.get(0);

      this.payload = new OptionPayload(this, "Reference Element:" + toString(), referencedElement, toString());
    }
  }

  public Element getReference()
  {
    return reference;
  }

  @Override
  public Element getElementNode()
  {
    return reference;
  }

  public OptionPayload getPayload()
  {
    return payload;
  }

  public String getURI()
  {
    return reference.getAttribute("URI");
  }

  public Element getReferencedElement()
  {
    return referencedElement;
  }

  public List<XPathElement> getXPaths()
  {
    return xpaths;
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof ReferenceElement)
    {
      ReferenceElement ref = (ReferenceElement) o;
      return ref.getURI().equals(getURI()) && ref.getXPaths().equals(getXPaths());
    }
    return false;
  }

  @Override
  public String toString()
  {
    return "URI=\"" + getURI() + "\"";
  }

  private Logger log()
  {
    return Logger.getLogger(getClass());
  }
  
  public String transformIDtoXPath() {
    Attr id = referencedElement.getAttributeNodeNS(NamespaceConstants.URI_NS_WSU, "Id");
    String prefix = "";
    String value = "";
    if (id.getPrefix() != null)
    {
      prefix = id.getPrefix() + ":";
      value = id.getValue();
    }
    else
    {
      value = referencedElement.getAttribute("Id");
    }
    return  "//*[@" + prefix + "Id='" + value + "']";
    
  }

  @Override
  public String getXPath()
  {
    if (workingXPath.isEmpty()) 
    {
      workingXPath = transformIDtoXPath();
    }
    return workingXPath;
  }

  @Override
  public void setXPath(String workingXPath)
  {
      this.workingXPath = workingXPath;
  }
}
