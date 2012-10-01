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
 * An AxisSpecifier consists of an AxisName, a NodeType and a NodeName.
 */
public class AxisSpecifier implements XPathPartInterface
{

  private String   axisSpecifier;
  private AxisName axisName;
  private NodeType nodeType;
  private NodeName nodeName;

  public AxisSpecifier(String axisSpecifier)
  {
    this.axisSpecifier = axisSpecifier;
    eval();
  }

  public String getAxisSpecifier()
  {
    return axisSpecifier;
  }

  public AxisName getAxisName()
  {
    return axisName;
  }

  public NodeType getNodeType()
  {
    return nodeType;
  }

  public NodeName getNodeName()
  {
    return nodeName;
  }

  @Override
  public String toString()
  {
    return axisSpecifier;
  }

  @Override
  public String toFullString()
  {
    return axisName.toFullString() + "::" + (nodeName != null ? nodeName.toFullString() : nodeType.toFullString());
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String) {
		  return equals(new AxisSpecifier((String) o));
	  }
    if (o instanceof AxisSpecifier)
    {
      AxisSpecifier ax = (AxisSpecifier) o;
      boolean sameNodeName = (ax.getNodeName() == getNodeName()) || (ax.getNodeName() != null && getNodeName() != null && ax
          .getNodeName().equals(getNodeName()));
      boolean sameNodeType = (ax.getNodeType() == getNodeType()) || (ax.getNodeType() != null && getNodeType() != null && ax
          .getNodeType().equals(getNodeType()));
      return ax.getAxisName().equals(getAxisName()) && sameNodeName && sameNodeType;
    }
    return false;
  }

  private void eval()
  {
    this.nodeName = null;
    this.nodeType = null;
    int start = 0;
    // abbrevs:
    if (axisSpecifier.isEmpty())
    {
      this.axisName = new AxisName("descendant-or-self");
      this.nodeType = new NodeType("node()");
      return;
    }
    else if (axisSpecifier.equals(".."))
    {
      this.axisName = new AxisName("parent");
      this.nodeType = new NodeType("node()");
      return;
    }
    else if (axisSpecifier.equals("."))
    {
      this.axisName = new AxisName("self");
      this.nodeType = new NodeType("node()");
      return;
    }
    else if (axisSpecifier.contains("::"))
    {
      start = axisSpecifier.indexOf("::");
      String axisName = axisSpecifier.substring(0, start);
      this.axisName = new AxisName(axisName);
      start += 2;
    }
    else if (axisSpecifier.charAt(0) == '@')
    {
      this.axisName = new AxisName("@");
      start = 1;
    }
    else
      this.axisName = new AxisName("child");
    String rest = axisSpecifier.substring(start);
    if (rest.equals("*"))
    {
      this.nodeType = new NodeType("*");
    }
    else if (rest.indexOf('(') > 0)
      this.nodeType = new NodeType(rest);
    else
      this.nodeName = new NodeName(rest);
  }
}
