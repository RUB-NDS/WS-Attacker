package wsattacker.plugin.signatureWrapping.schema;

import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

/**
 * This class is a NullObject imeplementation of the AnyElementPropertiesInterface.
 * It is used if no XML Schema Validation shall be performed.
 * It always returns that any element can have any wrapper element.
 */
public class NullAnyElementProperties implements AnyElementPropertiesInterface
{
  
  private Element documentElement;

  /**
   * NullAnyElementProperties is used if no SchemaAnalyser should be used.
   * Every documentElement is allowed to have any kind of child Elements.
   * @param documentElement
   */
  public NullAnyElementProperties(Element documentElement)
  {
    this.documentElement = documentElement;
  }

  @Override
  public Element getDocumentElement()
  {
    return documentElement;
  }

  @Override
  public String getProcessContentsAttribute()
  {
    return "lax";
  }

  @Override
  public String getNamespaceAttributeValue()
  {
    return "##any";
  }

  @Override
  public boolean needsWrapper(String childNamespaceURI)
  {
    return false;
  }

  @Override
  public int compareTo(AnyElementPropertiesInterface other)
  {
    return DomUtilities.getFastXPath(documentElement).compareTo(DomUtilities.getFastXPath(other.getDocumentElement()));
  }

  @Override
  public boolean equals(Object other)
  {
    if (other instanceof AnyElementProperties)
      return DomUtilities.getFastXPath(documentElement).equals(DomUtilities.getFastXPath(((AnyElementPropertiesInterface) other)
          .getDocumentElement()));
    return false;
  }

}
