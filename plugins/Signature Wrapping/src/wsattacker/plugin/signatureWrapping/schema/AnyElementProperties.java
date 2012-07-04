package wsattacker.plugin.signatureWrapping.schema;

import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

/**
 * Wrapper Class. Can be expanded if additional features are necessary.
 * 
 */
public class AnyElementProperties implements AnyElementPropertiesInterface
{

  Element anyElement, documentElement;

  public AnyElementProperties(Element anyElement,
                              Element documentElement)
  {
    this.anyElement = anyElement;
    this.documentElement = documentElement;
  }

  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface#getDocumentElement()
   */
  @Override
  public Element getDocumentElement()
  {
    return documentElement;
  }
  
  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface#getProcessContentsAttribute()
   */
  @Override
  public String getProcessContentsAttribute() {
    String processContents = anyElement.getAttribute("processContents");
    if (processContents == null || processContents.isEmpty())
      processContents = "strict";
    return processContents;
  }
  
  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface#getNamespaceAttributeValue()
   */
  @Override
  public String getNamespaceAttributeValue() {
    String namespace = anyElement.getAttribute("namespace");
    if (namespace == null || namespace.isEmpty())
      namespace = "##any";
    return namespace;
  }

  private boolean allowsDirectChildelements()
  {
    return getNamespaceAttributeValue().equals("##any");
  }

  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface#needsWrapper(java.lang.String)
   */
  @Override
  public boolean needsWrapper(String childNamespaceURI)
  {
    String namespace = anyElement.getAttribute("namespace");
    if (namespace != null && namespace.equals("##other"))
    {
      return documentElement.getNamespaceURI().equals(childNamespaceURI);
    }
    return !allowsDirectChildelements();
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
