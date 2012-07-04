package wsattacker.plugin.signatureWrapping.xpath.interfaces;

import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;

/**
 * Interafce which defines an XPath Weakness.
 * Concrete implementations will be:
 *  - AttribteWeakness
 *  - DescendantWeakness
 *  - Namespace Injection
 */
public interface XPathWeakness
{
  public int getNumberOfPossibilites();

  /**
   * abuse an XPath weakness. Important: The implementation is not allowed to change the references for signedElement or
   * payloadElement. This is needed for the decorator pattern!
   * 
   * @param index
   * @param signedElement
   * @param payloadElement
   * @throws InvalidWeaknessException
   */
  public void abuseWeakness(int index,
                            Element signedElement,
                            Element payloadElement)
                                                   throws InvalidWeaknessException;
}
