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
package wsattacker.library.signatureWrapping.option;

import java.util.*;
import wsattacker.library.signatureWrapping.xpath.weakness.util.XPathWeaknessTools;

public class PayloadOrderingHelper {

    public static void orderOuterToInner(List<Payload> payloadList) {
        List<Payload> copyList = new ArrayList<Payload>();
        // Move all but the first items from original List to a Copy
        for (int i = 1; i < payloadList.size(); ++i) {
            copyList.add(payloadList.get(i));
            payloadList.remove(i);
        }
        // Now insert all payloads but ordered
        main:
        while (!copyList.isEmpty()) {
            Payload cmp = copyList.remove(0);
            check:
            for (int i = 0; i < payloadList.size(); ++i) {
                Payload cur = payloadList.get(i);
                if (isOuter(cmp, cur)) {
                    payloadList.add(i, cmp);
                    continue main;
                }
            }
            payloadList.add(cmp);
        }
    }

    private static boolean isOuter(Payload outer, Payload maybeInner) {
        return (XPathWeaknessTools.isAncestorOf(outer.getSignedElement(), maybeInner.getSignedElement()) > 0);
    }

    private PayloadOrderingHelper() {
    }
}
