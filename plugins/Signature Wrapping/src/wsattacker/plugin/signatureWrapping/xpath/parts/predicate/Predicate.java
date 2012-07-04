package wsattacker.plugin.signatureWrapping.xpath.parts.predicate;

import java.util.ArrayList;
import java.util.List;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.util.XPathInspectorTools;

/**
 * A predicate is mainly a container for OrExpressions. 1 Predicate -> * OrExpression. 1 OrExpression -> *
 * AndExpression.
 */
public class Predicate implements XPathPartInterface
{
  private String             predicate;
  private List<OrExpression> orExpressions;

  public Predicate(String predicate)
  {
    this.predicate = predicate;
    this.orExpressions = new ArrayList<OrExpression>();
    eval();
  }

  public String getPredicate()
  {
    return predicate;
  }

  public List<OrExpression> getOrExpressions()
  {
    return orExpressions;
  }

  @Override
  public String toString()
  {
    return predicate;
  }

  @Override
  public String toFullString()
  {
    return XPathInspectorTools.implodeList(orExpressions, " ");
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String)
      return equals(new Predicate((String) o));
    if (o instanceof Predicate)
      return ((Predicate) o).getOrExpressions().equals(getOrExpressions());
    return false;
  }

  private void eval()
  {
    int prevOr = 0;
    int nextOr = XPathInspectorTools.nextString(predicate, " or ", prevOr);
    String orString;
    while (nextOr > 0)
    {
      orString = predicate.substring(prevOr, nextOr).trim();
      if (!orString.isEmpty())
        orExpressions.add(new OrExpression(orString));
      prevOr = nextOr + 4; // = nextOr + " or ".length()
      nextOr = XPathInspectorTools.nextString(predicate, " or ", prevOr);
    }
    orString = predicate.substring(prevOr).trim();
    if (!orString.isEmpty())
      orExpressions.add(new OrExpression(orString));
  }
}
