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

import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * An interface for the SchemaAnalyzer.
 * There are two implemetations for it:
 * 1) A Real Schema Analyzer
 * 2) A Null Schema Analyzer, which allows any element to have any child element.
 */
public interface SchemaAnalyzerInterface
{

  public abstract void setFilterList(List<QName> filterList);

  public abstract void appendSchema(Document newSchema);

  /**
   * Find an expansion point in the Schema starting with Node fromHere. The returned Elements are not part of the old
   * Document. Instead, a new Document is used where each possible but not occuring element is added. So, the original
   * Document will not be modified! Elements in the filterList will not be searched.
   * 
   * @param fromHere
   * @param filterList
   */
  public abstract List<AnyElementPropertiesInterface> findExpansionPoint(Element fromHere);

}
