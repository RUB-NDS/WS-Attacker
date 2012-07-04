package wsattacker.plugin.signatureWrapping.util.signature;

import org.w3c.dom.Element;

public interface ReferringElementInterface
{
  /**
   * @return The Reference element
   */
  public Element getElementNode();

  /**
   * @return The corresponding XPath Expression. Returns the tranformed ID XPath in case of an ID Reference.
   */
  public String getXPath(); // as every ID Reference can be transformed to an XPath.
  
  /**
   * Manually set an XPath which will be analyzed.
   */
  public void setXPath(String workingXPath);
}
