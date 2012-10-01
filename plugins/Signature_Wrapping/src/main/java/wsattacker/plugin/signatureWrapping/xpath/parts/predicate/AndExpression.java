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
    if (o instanceof String) {
		  return equals(new AndExpression((String) o));
	  }
    if (o instanceof AndExpression) {
		  return expression.equals(((ExpressionInterface) o).getExpression());
	  }
    return false;
  }
}
