package wsattacker.plugin.signatureWrapping.xpath.parts.predicate.factory;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidTypeException;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.AndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete.AttributeAndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete.LocalNameAndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete.NamespaceUriAndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete.PositionAndExpression;

public class AndExpressionFactory implements AndExpressionFactoryInterface
{

  @Override
  public AndExpression createAndExpression(String expression)
  {
      try
      {
        return new AttributeAndExpression(expression);
      }
      catch (InvalidTypeException e)
      {
        // Nothing to do, just ignore
      }
      
      
      try
      {
        return new PositionAndExpression(expression);
      }
      catch (InvalidTypeException e)
      {
        // Nothing to do, just ignore
      }
      
      
      try
      {
        return new LocalNameAndExpression(expression);
      }
      catch (InvalidTypeException e)
      {
        // Nothing to do, just ignore
      }
      
      
      try
      {
        return new NamespaceUriAndExpression(expression);
      }
      catch (InvalidTypeException e)
      {
        // Nothing to do, just ignore
      }
      
      
    // No special AndExpression found
    // return generic one
    return new AndExpression(expression);
  }

}
