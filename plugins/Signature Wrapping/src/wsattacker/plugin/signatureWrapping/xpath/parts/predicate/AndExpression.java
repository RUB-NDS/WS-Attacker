package wsattacker.plugin.signatureWrapping.xpath.parts.predicate;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.ExpressionInterface;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;

/**
 * Smallest part of an Expression. Can be anything what is important for the analysis, e.g. an attribute specifier.
 */
public class AndExpression implements XPathPartInterface, ExpressionInterface
{
  protected String expression;

  public AndExpression(String expression)
  {
    this.expression = expression;
  }

  @Override
  public String getExpression()
  {
    return expression;
  }

  @Override
  public String toString()
  {
    return expression;
  }

  @Override
  public String toFullString()
  {
    return expression;
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String)
      return equals(new AndExpression((String) o));
    if (o instanceof AndExpression)
      return expression.equals(((ExpressionInterface) o).getExpression());
    return false;
  }
}
