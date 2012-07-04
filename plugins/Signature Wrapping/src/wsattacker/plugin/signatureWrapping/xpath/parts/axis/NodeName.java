package wsattacker.plugin.signatureWrapping.xpath.parts.axis;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;

/**
 * The NodeName has a prefix and a localname, whereas the Prefix may be empty.
 */
public class NodeName implements XPathPartInterface
{

  private String nodeName, prefix, localname;

  public NodeName(String nodeName)
  {
    this.nodeName = nodeName;
    eval();
  }

  private void eval()
  {
    int index = nodeName.indexOf(':');
    if (index > 0)
    {
      prefix = nodeName.substring(0, index);
      localname = nodeName.substring(index + 1);
    }
    else
    {
      prefix = "";
      localname = nodeName;
    }
  }

  public String getNodeName()
  {
    return nodeName;
  }

  public String getPrefix()
  {
    return prefix;
  }

  public String getLocalname()
  {
    return localname;
  }

  @Override
  public String toString()
  {
    return nodeName;
  }

  @Override
  public String toFullString()
  {
    return toString();
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String || o instanceof Step)
      return o.equals(toString());
    return false;
  }
}
