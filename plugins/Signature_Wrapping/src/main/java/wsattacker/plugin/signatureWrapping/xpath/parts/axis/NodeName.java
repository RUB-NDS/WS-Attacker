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
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;

/**
 * The NodeName has a prefix and a localname, whereas the Prefix may be empty.
 */
public class NodeName implements XPathPartInterface
{

  private String nodeName, prefix, localname;

  public NodeName(String nodeName)
  {
    this.nodeName = nodeName;
    eval();
  }

  private void eval()
  {
    int index = nodeName.indexOf(':');
    if (index > 0)
    {
      prefix = nodeName.substring(0, index);
      localname = nodeName.substring(index + 1);
    }
    else
    {
      prefix = "";
      localname = nodeName;
    }
  }

  public String getNodeName()
  {
    return nodeName;
  }

  public String getPrefix()
  {
    return prefix;
  }

  public String getLocalname()
  {
    return localname;
  }

  @Override
  public String toString()
  {
    return nodeName;
  }

  @Override
  public String toFullString()
  {
    return toString();
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String || o instanceof Step) {
		  return o.equals(toString());
	  }
    return false;
  }
}
