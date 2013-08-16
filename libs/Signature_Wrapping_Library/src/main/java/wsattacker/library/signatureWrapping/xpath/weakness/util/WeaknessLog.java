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
package wsattacker.library.signatureWrapping.xpath.weakness.util;

import java.util.*;

/**
 * Simple logging class.
 * Each XPathWeakness can append a simple String to the log.
 */
public final class WeaknessLog {

    private static List<String> log = new ArrayList<String>();

    /**
     * Cleans all saved log entries.
     */
    public static void clean() {
        log.clear();
    }

    /**
     * Append a simple string.
     *
     * @param message
     */
    public static void append(String message) {
        log.add(message);
    }

    /**
     * Returns the entries as a List.
     *
     * @return List of Logentries.
     */
    public static List<String> get() {
        return log;
    }

    /**
     * Returns the list as a String representation.
     *
     * @return Logstring.
     */
    public static String representation() {
        StringBuilder sb = new StringBuilder();
        for (String s : log) {
            sb.append(s).append(("\n"));
        }
        return sb.toString().trim();
    }

    private WeaknessLog() {
    }

}
