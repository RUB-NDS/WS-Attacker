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
package wsattacker.library.signatureWrapping.util.signature.weakness;

import java.util.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public final class PrefixRewriter {

    public static void rewritePrefix(Element element, String oldPrefix, String newPrefix) {
        rewritePrefix(element, oldPrefix, newPrefix, new ArrayList<Element>(0));
    }

    public static void rewritePrefix(Element element, String oldPrefix, String newPrefix, List<Element> untouchedElementList) {
        List<Element> childElementList = DomUtilities.getAllChildElements(element);
        Document doc = element.getOwnerDocument();

        // self rewriting
        if (!untouchedElementList.contains(element)) {
            if (element.getPrefix() != null && element.getPrefix().equals(oldPrefix)) {
                doc.renameNode(element, element.getNamespaceURI(), newPrefix + ":" + element.getLocalName());
            }
            for (Element task : childElementList) {
                if (!untouchedElementList.contains(task)) {
                    rewritePrefix(task, oldPrefix, newPrefix, untouchedElementList);
                }
            }
        }
    }

    private PrefixRewriter() {
    }
}
