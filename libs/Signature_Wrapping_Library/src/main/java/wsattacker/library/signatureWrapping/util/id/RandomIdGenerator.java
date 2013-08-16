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
package wsattacker.library.signatureWrapping.util.id;

import static org.apache.commons.lang.RandomStringUtils.random;
import static org.apache.commons.lang.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang.RandomStringUtils.randomAlphanumeric;

public final class RandomIdGenerator {

    private RandomIdGenerator() {
    }

    public static String generate_8_4_4_12_ID() {
        String one = randomAlphanumeric(8);
        String two = randomAlphanumeric(4);
        String three = randomAlphanumeric(4);
        String four = randomAlphanumeric(12);
        return String.format("_%s-%s-%s-%s", one, two, three, four);
    }

    public static String generate_8_4_4_4_12_ID() {
        String one = randomAlphanumeric(8);
        String two = randomAlphanumeric(4);
        String three = randomAlphanumeric(4);
        String four = randomAlphanumeric(4);
        String five = randomAlphanumeric(12);
        return String.format("_%s-%s-%s-%s-%s", one, two, three, four, five);
    }

    public static String generate_32_ID() {
        return generate_ID(32);
    }

    public static String generate_ID(int length) {
        return randomAlphabetic(1) + randomAlphanumeric(length - 1);
    }

    /**
     * Change a given ID String to a new one.
     * Keeps format, which means, that numbers are substituted by numbers,
     * small by small and capital by capital letters.
     * Dots, dashes and other special chars are kept.
     *
     * @param originalID
     *
     * @return
     */
    public static String rotate_ID(String originalID) {
        StringBuffer sb = new StringBuffer(originalID.length());
        for (int i = 0; i < originalID.length(); ++i) {
            char c = originalID.charAt(i);
            if (c >= 'a' && c <= 'z') {
                sb.append(random(1, 'a', 'z', true, true));
            } else if (c >= 'A' && c <= 'Z') {
                sb.append(random(1, 'A', 'Z', true, true));
            } else if (c >= '0' && c <= '9') {
                sb.append(random(1, '0', '9', true, true));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
