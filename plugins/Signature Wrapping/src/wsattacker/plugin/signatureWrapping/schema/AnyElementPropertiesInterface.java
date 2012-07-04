package wsattacker.plugin.signatureWrapping.schema;

import org.w3c.dom.Element;

public interface AnyElementPropertiesInterface extends Comparable<AnyElementPropertiesInterface>
{

  /**
   * @return the element which has <xs:any> child element within the current working Document.
   */
  public abstract Element getDocumentElement();

  /**
   * @return the value of the processContents attribute
   */
  public abstract String getProcessContentsAttribute();

  /**
   * @return the value of the namespace attribute
   */
  public abstract String getNamespaceAttributeValue();

  /**
   * Compares the namespace of the parent element with the one of the child element.
   * If they are the same and the namespace attribute is ##other, it returns true.
   * @return if the child elements needs a wrapper.
   */
  public abstract boolean needsWrapper(String childNamespaceURI);

}
