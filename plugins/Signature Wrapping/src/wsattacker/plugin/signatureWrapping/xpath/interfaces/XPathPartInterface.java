package wsattacker.plugin.signatureWrapping.xpath.interfaces;

/**
 * Simple Interface wich describes a part of an XPath.
 * Parts are e.g. Steps, Expressions, AxisSpecifier, ...
 */
public interface XPathPartInterface
{
  /**
   * Get the Full-String Representation of an XPathPart, e.g. "//" will be extended to "ancestor-or-self"
   * 
   * @return
   */
  public String toFullString();
}
