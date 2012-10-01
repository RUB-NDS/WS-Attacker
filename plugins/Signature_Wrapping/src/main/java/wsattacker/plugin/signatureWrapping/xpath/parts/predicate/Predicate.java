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
    if (o instanceof String) {
				  return equals(new Predicate((String) o));
		  }
    if (o instanceof Predicate) {
				  return ((Predicate) o).getOrExpressions().equals(getOrExpressions());
		  }
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
      if (!orString.isEmpty()) {
					orExpressions.add(new OrExpression(orString));
			}
      prevOr = nextOr + 4; // = nextOr + " or ".length()
      nextOr = XPathInspectorTools.nextString(predicate, " or ", prevOr);
    }
    orString = predicate.substring(prevOr).trim();
    if (!orString.isEmpty()) {
				  orExpressions.add(new OrExpression(orString));
		  }
  }
}
