package wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidTypeException;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.factory.FunctionAndExpression;

public class NamespaceUriAndExpression extends FunctionAndExpression
{

  public NamespaceUriAndExpression(String expression)
                                                     throws InvalidTypeException
  {
    super(expression, "namespace-uri()");
  }

}
