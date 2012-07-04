package wsattacker.plugin.signatureWrapping.schema;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import wsattacker.util.SortedUniqueList;

/**
 * NullSchemaAnalyser is a XML Schema Analyser which will say that
 * every child in the document can have <xs:any> child element.
 * Thus, weaknesses can be used as if the server does not
 * validate any kind of XML Schema.
 */
public class NullSchemaAnalyzer implements SchemaAnalyzerInterface
{
  
  List<QName> filterList = new ArrayList<QName>();

  @Override
  public void setFilterList(List<QName> filterList)
  {
    this.filterList = filterList;
  }

  @Override
  public void appendSchema(Document newSchema)
  {
    // Nothing to do
    
  }
  
  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.SchemaAnalyserInterface#findExpansionPoint(org.w3c.dom.Element)
   */
  @Override
  public List<AnyElementPropertiesInterface> findExpansionPoint(Element fromHere)
  {
    List<AnyElementPropertiesInterface> result = new SortedUniqueList<AnyElementPropertiesInterface>();
    findExpansionPoint(result, fromHere);
    return result;
  }

  private void findExpansionPoint(List<AnyElementPropertiesInterface> result,
                                  Element start)
  {
    if (filterList.contains(new QName(start.getNamespaceURI(), start.getLocalName())))
    {
      return;
    }
    result.add(new NullAnyElementProperties(start));
    // Recursive with all child elements
    NodeList theChildren = start.getChildNodes();
    for (int i = 0; i < theChildren.getLength(); ++i)
      if (theChildren.item(i).getNodeType() == Node.ELEMENT_NODE)
        findExpansionPoint(result, (Element) theChildren.item(i));
  }

}
