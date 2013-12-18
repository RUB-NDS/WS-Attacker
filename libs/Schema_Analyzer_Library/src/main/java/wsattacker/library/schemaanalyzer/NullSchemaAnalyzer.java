/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.library.schemaanalyzer;

import java.util.*;
import javax.xml.namespace.QName;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * NullSchemaAnalyser is a XML Schema Analyser which will say that
 * every child in the document can have <xs:any> child element.
 * Thus, weaknesses can be used as if the server does not
 * validate any kind of XML Schema.
 */
public class NullSchemaAnalyzer implements SchemaAnalyzer {

    List<QName> filterList = new ArrayList<QName>();

    @Override
    public void setFilterList(List<QName> filterList) {
        this.filterList = filterList;
    }

    @Override
    public void appendSchema(Document newSchema) {
        // Nothing to do
    }

    /*
     * (non-Javadoc)
     * @see
     * wsattacker.plugin.signatureWrapping.schema.SchemaAnalyserInterface#findExpansionPoint(org.w3c.dom.Element)
     */
    @Override
    public Set<AnyElementProperties> findExpansionPoint(Element fromHere) {
        Set<AnyElementProperties> result = new TreeSet<AnyElementProperties>();
        findExpansionPoint(result, fromHere);
        return result;
    }

    private void findExpansionPoint(Set<AnyElementProperties> result,
      Element start) {
        if (filterList.contains(new QName(start.getNamespaceURI(), start.getLocalName()))) {
            return;
        }
        result.add(new NullAnyElementProperties(start));
        // Recursive with all child elements
        NodeList theChildren = start.getChildNodes();
        for (int i = 0; i < theChildren.getLength(); ++i) {
            if (theChildren.item(i).getNodeType() == Node.ELEMENT_NODE) {
                findExpansionPoint(result, (Element) theChildren.item(i));
            }
        }
    }
}
