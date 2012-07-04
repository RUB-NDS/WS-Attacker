package wsattacker.plugin.signatureWrapping.xpath.parts.axis;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;

/**
 * Class for specifing the Axis of the Node, e.g. ancestor or descendant.
 */
public class AxisName implements XPathPartInterface
{

  public final static String[] AxisName =
                                        { "ancestor", "ancestor-or-self", "attribute", "child", "descendant", "descendant-or-self", "following", "following-sibling", "namespace", "parent", "preceding", "preceding-sibling", "self" };

  private String               axisName;

  public AxisName(String axisName)
  {
    this.axisName = axisName;
  }

  public String getAxisName()
  {
    return axisName;
  }

  @Override
  public String toString()
  {
    return axisName;
  }

  @Override
  public String toFullString()
  {
    if (axisName.isEmpty())
      return "child";
    if (axisName.equals("@"))
      return "attribute";
    return axisName;
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String)
      return equals(new AxisName((String) o));
    if (o instanceof AxisName)
      return ((AxisName) o).toFullString().equals(toFullString());
    return false;
  }
}
