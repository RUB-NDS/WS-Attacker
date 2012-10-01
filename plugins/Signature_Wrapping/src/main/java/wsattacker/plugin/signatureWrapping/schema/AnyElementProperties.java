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
 * Wrapper Class. Can be expanded if additional features are necessary.
 * 
 */
public class AnyElementProperties implements AnyElementPropertiesInterface
{

  Element anyElement, documentElement;

  public AnyElementProperties(Element anyElement,
                              Element documentElement)
  {
    this.anyElement = anyElement;
    this.documentElement = documentElement;
  }

  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface#getDocumentElement()
   */
  @Override
  public Element getDocumentElement()
  {
    return documentElement;
  }
  
  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface#getProcessContentsAttribute()
   */
  @Override
  public String getProcessContentsAttribute() {
    String processContents = anyElement.getAttribute("processContents");
    if (processContents == null || processContents.isEmpty()) {
		  processContents = "strict";
	  }
    return processContents;
  }
  
  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface#getNamespaceAttributeValue()
   */
  @Override
  public String getNamespaceAttributeValue() {
    String namespace = anyElement.getAttribute("namespace");
    if (namespace == null || namespace.isEmpty()) {
		  namespace = "##any";
	  }
    return namespace;
  }

  private boolean allowsDirectChildelements()
  {
    return getNamespaceAttributeValue().equals("##any");
  }

  /* (non-Javadoc)
   * @see wsattacker.plugin.signatureWrapping.schema.AnyElementPropertiesInterface#needsWrapper(java.lang.String)
   */
  @Override
  public boolean needsWrapper(String childNamespaceURI)
  {
    boolean needsWrapper;
    String namespace = anyElement.getAttribute("namespace");
    if (namespace != null && namespace.equals("##other"))
    {
      needsWrapper = documentElement.getNamespaceURI().equals(childNamespaceURI);
    }
    else {
	    needsWrapper = !allowsDirectChildelements();
    }
    return needsWrapper;
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
