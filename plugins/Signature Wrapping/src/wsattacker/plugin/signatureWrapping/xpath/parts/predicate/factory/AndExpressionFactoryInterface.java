package wsattacker.plugin.signatureWrapping.xpath.parts.predicate.factory;

import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.AndExpression;

public interface AndExpressionFactoryInterface
{
  public AndExpression createAndExpression(String expression);
}
