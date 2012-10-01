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
package wsattacker.plugin.signatureWrapping.schema;

import org.w3c.dom.Element;

public interface AnyElementPropertiesInterface extends Comparable<AnyElementPropertiesInterface>
{

  /**
   * @return the element which has <xs:any> child element within the current working Document.
   */
  public abstract Element getDocumentElement();

  /**
   * @return the value of the processContents attribute
   */
  public abstract String getProcessContentsAttribute();

  /**
   * @return the value of the namespace attribute
   */
  public abstract String getNamespaceAttributeValue();

  /**
   * Compares the namespace of the parent element with the one of the child element.
   * If they are the same and the namespace attribute is ##other, it returns true.
   * @return if the child elements needs a wrapper.
   */
  public abstract boolean needsWrapper(String childNamespaceURI);

}
