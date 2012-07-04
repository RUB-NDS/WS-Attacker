package wsattacker.plugin.signatureWrapping.xpath.parts.predicate;

import java.util.ArrayList;
import java.util.List;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.ExpressionInterface;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.factory.AndExpressionFactory;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.factory.AndExpressionFactoryInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.util.XPathInspectorTools;

/**
 * An OrExpression is mainly a container for AndExpressions.
 */
public class OrExpression implements XPathPartInterface, ExpressionInterface
{
  /**
   * Factory for creating special andExpressions. Global access.. can be changed to another implementation.
   */
  public static AndExpressionFactoryInterface andFactory = new AndExpressionFactory();

  private String                              expression;
  private List<AndExpression>                 andExpressions;

  public OrExpression(String expression)
  {
    this.expression = expression;
    this.andExpressions = new ArrayList<AndExpression>();
    eval();
  }

  public List<AndExpression> getAndExpressions()
  {
    return andExpressions;
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
    return XPathInspectorTools.implodeList(andExpressions, " ");
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String)
      return equals(new OrExpression((String) o));
    if (o instanceof OrExpression)
      return expression.equals(((ExpressionInterface) o).getExpression());
    return false;
  }

  private void eval()
  {
    int prevAnd = 0;
    int nextAnd = XPathInspectorTools.nextString(expression, " and ", prevAnd);
    String andString;
    while (nextAnd > 0)
    {
      andString = expression.substring(prevAnd, nextAnd).trim();
      if (!andString.isEmpty())
        andExpressions.add(andFactory.createAndExpression(andString));
      prevAnd = nextAnd + 5; // = nextOr + " and ".length()
      nextAnd = XPathInspectorTools.nextString(expression, " and ", prevAnd);
    }
    andString = expression.substring(prevAnd).trim();
    if (!andString.isEmpty())
      andExpressions.add(andFactory.createAndExpression(andString));
  }
}
