package wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidTypeException;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.factory.FunctionAndExpression;

public class LocalNameAndExpression extends FunctionAndExpression
{

  public LocalNameAndExpression(String expression)
                                                    throws InvalidTypeException
  {
    super(expression, "local-name()");
  }

}
