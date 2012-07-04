package wsattacker.plugin.signatureWrapping.xpath.parts.predicate.factory;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidTypeException;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.AndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.util.XPathInspectorTools;

public abstract class FunctionAndExpression extends AndExpression
{
  
  protected String functionName, value;

  public FunctionAndExpression(String expression, String functionName) throws InvalidTypeException
  {
    super(expression);
    this.functionName = functionName;
    String functionNameEq = functionName + "=";
    
    if (expression.startsWith(functionNameEq)) {
      int start = functionNameEq.length();
      
      // detect if correct quote is used
      char quote = expression.charAt(start);
      if (quote != '"' && quote != '\'')
        throw new InvalidTypeException();
      
      int end = XPathInspectorTools.nextChar(expression, quote, start+1);
      if (end < 0)
        throw new InvalidTypeException();
      
      this.value = expression.substring(start+1, end);
      
    } else
      throw new InvalidTypeException();
  }

  public String getFunctionName()
  {
    return functionName;
  }

  public String getValue()
  {
    return value;
  }

}
