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
package wsattacker.plugin.signatureWrapping.util.signature;

import org.w3c.dom.Element;

public interface ReferringElementInterface
{
  /**
   * @return The Reference element
   */
  public Element getElementNode();

  /**
   * @return The corresponding XPath Expression. Returns the tranformed ID XPath in case of an ID Reference.
   */
  public String getXPath(); // as every ID Reference can be transformed to an XPath.
  
  /**
   * Manually set an XPath which will be analyzed.
   */
  public void setXPath(String workingXPath);
}
