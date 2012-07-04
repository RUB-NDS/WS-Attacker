package wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidTypeException;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.AndExpression;

public class AttributeAndExpression extends AndExpression
{
  private static final String attribute = "attribute::";

  private String              prefix    = "", localname = "", value = "";

  public AttributeAndExpression(String expression) throws InvalidTypeException
  {
    super(expression);

    String tmp = "";
    if (expression.startsWith("@"))
      tmp = expression.substring(1).trim();
    else if (expression.startsWith(attribute))
      tmp = expression.substring(attribute.length()).trim();
    else
      throw new InvalidTypeException();

    int equalpos = tmp.indexOf('=');
    // abort if no equal sign or equalsign is not followed by quotes
    if (equalpos < 1 || (equalpos + 2) > tmp.length())
      return;

    // Get Name

    String nodename = tmp.substring(0, equalpos);
    int colonpos = nodename.indexOf(':');
    if (colonpos > 0 && colonpos < nodename.length())
    {
      prefix = nodename.substring(0, colonpos);
      localname = nodename.substring(colonpos + 1);
    }
    else
    {
      localname = nodename;
    }

    // Get Value

    char quote = tmp.charAt(equalpos + 1);

    int endquote = tmp.lastIndexOf(quote);
    if (equalpos + 1 == endquote)
      return;

    value = tmp.substring(equalpos + 2, endquote);
  }

  public String getPrefix()
  {
    return prefix;
  }

  public String getLocalname()
  {
    return localname;
  }

  public String getValue()
  {
    return value;
  }

}
