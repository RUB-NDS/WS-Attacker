/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2011 Christian Mainka
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
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
      if (quote != '"' && quote != '\'') {
					throw new InvalidTypeException();
			}
      
      int end = XPathInspectorTools.nextChar(expression, quote, start+1);
      if (end < 0) {
					throw new InvalidTypeException();
			}
      
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
