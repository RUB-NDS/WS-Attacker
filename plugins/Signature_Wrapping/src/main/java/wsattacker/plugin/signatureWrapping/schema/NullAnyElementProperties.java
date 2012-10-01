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

import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

/**
 * This class is a NullObject imeplementation of the AnyElementPropertiesInterface.
 * It is used if no XML Schema Validation shall be performed.
 * It always returns that any element can have any wrapper element.
 */
public class NullAnyElementProperties implements AnyElementPropertiesInterface
{
  
  private Element documentElement;

  /**
   * NullAnyElementProperties is used if no SchemaAnalyser should be used.
   * Every documentElement is allowed to have any kind of child Elements.
   * @param documentElement
   */
  public NullAnyElementProperties(Element documentElement)
  {
    this.documentElement = documentElement;
  }

  @Override
  public Element getDocumentElement()
  {
    return documentElement;
  }

  @Override
  public String getProcessContentsAttribute()
  {
    return "lax";
  }

  @Override
  public String getNamespaceAttributeValue()
  {
    return "##any";
  }

  @Override
  public boolean needsWrapper(String childNamespaceURI)
  {
    return false;
  }

  @Override
  public int compareTo(AnyElementPropertiesInterface other)
  {
    return DomUtilities.getFastXPath(documentElement).compareTo(DomUtilities.getFastXPath(other.getDocumentElement()));
  }

  @Override
  public boolean equals(Object other)
  {
	boolean isEqual = false;
    if (other instanceof AnyElementProperties) {
		isEqual = DomUtilities.getFastXPath(documentElement).equals(DomUtilities.getFastXPath(((AnyElementPropertiesInterface) other)
					  .getDocumentElement()));
	}
    return isEqual;
  }

}
