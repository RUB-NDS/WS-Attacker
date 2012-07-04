package wsattacker.plugin.signatureWrapping.xpath.analysis;

import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

/**
 * Wrapper class which hold the properties for a payload element.
 */
public class WrapperProperties
{
  private AnyElementPropertiesInterface anyElementPorperties;
  private Element              payloadElement;
  private int                  possiblePositions;
  private boolean              wrapperNeeded;

  /**
   * Constructor.
   * @param anyElementPorperties
   * @param payloadElement
   */
  public WrapperProperties(AnyElementPropertiesInterface anyElementPorperties,
                           Element payloadElement)
  {
    this.anyElementPorperties = anyElementPorperties;
    this.payloadElement = payloadElement;
    this.possiblePositions = 1 + DomUtilities.getAllChildElements(anyElementPorperties.getDocumentElement()).size();
    this.wrapperNeeded = anyElementPorperties.needsWrapper(payloadElement.getNamespaceURI());
  }

  public AnyElementPropertiesInterface getAnyElementPorperties()
  {
    return anyElementPorperties;
  }

  public Element getPayloadElement()
  {
    return payloadElement;
  }

  /**
   * @return number of possible positions to place the wrapper element. Depends on the amount of child elements of the extension point element.
   */
  public int getPossiblePositions()
  {
    return possiblePositions;
  }

  /**
   * @return is a wrapper element needed?
   */
  public boolean isWrapperNeeded()
  {
    return wrapperNeeded;
  }
}
