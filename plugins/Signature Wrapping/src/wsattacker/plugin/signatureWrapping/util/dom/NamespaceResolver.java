package wsattacker.plugin.signatureWrapping.util.dom;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.NamespaceContext;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;

import wsattacker.util.SortedUniqueList;

/**
 * This class is able to read in all prefix/namespace URI pairs and resolve user requests
 * 
 */
public class NamespaceResolver implements NamespaceContext
{
  Map<String, String>       prefixUriMap;

  Map<String, List<String>> uriPrefixMap;
  String                    defaultNamespace = "";

  /**
   * Constructor with Document Object
   * 
   * @param doc
   */
  public NamespaceResolver(Document doc)
  {
    prefixUriMap = new HashMap<String, String>();
    uriPrefixMap = new HashMap<String, List<String>>();
    allNamespaces(doc.getDocumentElement());
// System.out.println("Prefix-Uri Map:\n" + prefixUriMap.toString());
// System.out.println("Uri-Prefix Map:\n" + uriPrefixMap);
  }

  /**
   * Reads all namespaces
   * 
   * @param ele
   * @param nsList
   */
  private void allNamespaces(Element ele)
  {
    NamedNodeMap attributes = ele.getAttributes();
    for (int i = 0; i < attributes.getLength(); ++i)
    {
      Attr attribute = (Attr) attributes.item(i);
      if (attribute.getPrefix() != null && attribute.getNamespaceURI() != null)
      {
        String prefix = attribute.getPrefix();
        String uri = attribute.getNamespaceURI();
        prefixUriMap.put(prefix, uri);
        if (!uriPrefixMap.containsKey(uri))
        {
          uriPrefixMap.put(uri, new SortedUniqueList<String>());
        }
        uriPrefixMap.get(uri).add(prefix);
      }
    }
    String prefix = ele.getPrefix();
    String uri = ele.getNamespaceURI();
    if (prefix != null && uri != null)
    {
      prefixUriMap.put(prefix, uri);
      if (!uriPrefixMap.containsKey(uri))
      {
        uriPrefixMap.put(uri, new SortedUniqueList<String>());
      }
      uriPrefixMap.get(uri).add(prefix);
    }
    NodeList children = ele.getChildNodes();
    for (int i = 0; i < children.getLength(); ++i)
    {
      if (children.item(i).getNodeType() == Element.ELEMENT_NODE)
        allNamespaces((Element) children.item(i));
    }
  }

  /**
   * Returns the namespace URI for a given prefix
   */
  @Override
  public String getNamespaceURI(String prefix)
  {
    if (prefix == null)
      return defaultNamespace;
    return prefixUriMap.get(prefix);
  }

  /**
   * Adds a prefix/namespace URI pair to the known list
   * 
   * @param prefix
   * @param uri
   */
  public void addNamespace(String prefix,
                           String uri)
  {
    prefixUriMap.put(prefix, uri);
  }

  @Override
  public String getPrefix(String namespaceURI)
  {
    return uriPrefixMap.get(namespaceURI).get(0);
  }

  @Override
  public Iterator<String> getPrefixes(String namespaceURI)
  {
    return uriPrefixMap.get(namespaceURI).iterator();
  }

  public Map<String, String> getPrefixUriMap()
  {
    return prefixUriMap;
  }

  public Map<String, List<String>> getUriPrefixMap()
  {
    return uriPrefixMap;
  }
}
