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
package wsattacker.plugin.signatureWrapping.xpath.parts.axis;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;

/**
 * Class for specifing the Axis of the Node, e.g. ancestor or descendant.
 */
public class AxisName implements XPathPartInterface
{

  public final static String[] AxisName =
                                        { "ancestor", "ancestor-or-self", "attribute", "child", "descendant", "descendant-or-self", "following", "following-sibling", "namespace", "parent", "preceding", "preceding-sibling", "self" };

  private String               axisName;

  public AxisName(String axisName)
  {
    this.axisName = axisName;
  }

  public String getAxisName()
  {
    return axisName;
  }

  @Override
  public String toString()
  {
    return axisName;
  }

  @Override
  public String toFullString()
  {
    if (axisName.isEmpty()) {
		  return "child";
	  }
    if (axisName.equals("@")) {
		  return "attribute";
	  }
    return axisName;
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String) {
		  return equals(new AxisName((String) o));
	  }
    if (o instanceof AxisName) {
		  return ((AxisName) o).toFullString().equals(toFullString());
	  }
    return false;
  }
}
