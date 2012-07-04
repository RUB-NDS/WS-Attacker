package wsattacker.plugin.signatureWrapping.util.signature;

import java.util.ArrayList;
import java.util.List;

import javax.xml.xpath.XPathExpressionException;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

public class XPathElement implements ReferringElementInterface
{
  private Element             xpathElement;
  private List<OptionPayload> payloads;
  private List<Element>       matchedElements;
  private String              workingXPath;

  public XPathElement(Element xpath)
  {
    this.xpathElement = xpath;
    this.workingXPath = "";
    payloads = new ArrayList<OptionPayload>();
    log().trace("Searching matched Elements for " + toString());
    // Get the matched Elements by this XPath
    matchedElements = new ArrayList<Element>();
    try
    {
      matchedElements = DomUtilities.evaluateXPath(xpath.getOwnerDocument(), getExpression());
    }
    catch (XPathExpressionException e)
    {
    }

    log().trace("Found: " + matchedElements);
    // Add an OptionPayload for each match
    int anz = matchedElements.size();
    for (int i=0; i<anz; ++i)
    {
      Element signedElement = matchedElements.get(i);
      String addtionalInfo = "";
      if(anz > 1)
        addtionalInfo = " #"+i;
      OptionPayload o = new OptionPayload(this, "XPath: " + getExpression() + addtionalInfo, signedElement, getExpression());
      payloads.add(o);
    }
  }

  @Override
  public String getXPath()
  {
      if (workingXPath.isEmpty())
      {
        workingXPath = xpathElement.getTextContent();
      }
      return workingXPath;
  }

  @Override
  public void setXPath(String workingXPath)
  {
      this.workingXPath = workingXPath;
  }

  public Element getXPathElement()
  {
    return xpathElement;
  }

  @Override
  public Element getElementNode()
  {
    return xpathElement;
  }

  public List<OptionPayload> getPayloads()
  {
    return payloads;
  }

  public String getExpression()
  {
    return xpathElement.getTextContent();
  }

  public String getFilter()
  {
    return xpathElement.getAttribute("Filter");
  }

  public List<Element> getReferencedElements()
  {
    return matchedElements;
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof XPathElement)
    {
      XPathElement xpe = (XPathElement) o;
      return xpe.getFilter().equals(getFilter()) && xpe.getExpression().equals(getExpression());
    }
    return false;
  }

  @Override
  public String toString()
  {
    return "xpath=\"" + getExpression() + "\"";
  }

  private Logger log()
  {
    return Logger.getLogger(getClass());
  }
}
