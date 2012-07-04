package wsattacker.plugin.signatureWrapping.xpath.parts.axis;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;

/**
 * The NodeType can be "text", "comment", "node", "processing-instruction".
 */
public class NodeType implements XPathPartInterface
{
  public static String[] nodeTypes =
                                   { "text", "comment", "node", "processing-instruction" };

  private String         nodeType, nodeTypeName, nodeTypeArgument;

  public NodeType(String nodeType)
  {
    this.nodeType = nodeType;
    eval();
  }

  public String getNodeType()
  {
    return nodeType;
  }

  public String getNodeTypeName()
  {
    return nodeTypeName;
  }

  public String getNodeTypeArguments()
  {
    return nodeTypeArgument;
  }

  @Override
  public String toString()
  {
    return nodeType;
  }

  @Override
  public String toFullString()
  {
    return getNodeTypeName() + "(" + getNodeTypeArguments() + ")";
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String)
      return equals(new NodeType((String) o));
    if (o instanceof NodeType)
      return ((NodeType) o).getNodeTypeName().equals(getNodeTypeName()) && ((NodeType) o).getNodeTypeArguments()
          .equals(getNodeTypeArguments());
    return false;
  }

  private void eval()
  {
    if (this.nodeType.equals("*"))
    {
      this.nodeTypeName = "node";
      this.nodeTypeArgument = "";
      return;
    }
    this.nodeTypeName = nodeType.substring(0, nodeType.indexOf('('));
    this.nodeTypeArgument = nodeType.substring(nodeType.indexOf('(') + 1, nodeType.lastIndexOf(')'));
  }
}
