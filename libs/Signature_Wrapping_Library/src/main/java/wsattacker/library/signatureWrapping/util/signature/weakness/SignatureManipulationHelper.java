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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.library.signatureWrapping.util.signature.weakness;

import java.util.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.library.signatureWrapping.util.signature.NamespaceConstants;

public final class SignatureManipulationHelper {

    public static void doubleSignature(Document msg, int whichToDouble, int whichToReplace) {
        List<Element> signatures = DomUtilities.findChildren(msg, "Signature", NamespaceConstants.URI_NS_DS, true);
        Element clone = (Element) signatures.get(whichToDouble).cloneNode(true);
        Element toReplace = signatures.get(whichToReplace);
        toReplace.getParentNode().replaceChild(clone, toReplace);
    }

    public static void removeSignature(Document msg, int which) {
        List<Element> signatures = DomUtilities.findChildren(msg, "Signature", NamespaceConstants.URI_NS_DS, true);
        Element toRemove = signatures.get(which);
        toRemove.getParentNode().removeChild(toRemove);
    }

    private SignatureManipulationHelper() {
    }
}
