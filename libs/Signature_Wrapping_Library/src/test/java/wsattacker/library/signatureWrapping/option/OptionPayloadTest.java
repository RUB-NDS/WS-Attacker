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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.signatureWrapping.util.Signer;
import wsattacker.library.signatureWrapping.util.SoapTestDocument;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;

public class OptionPayloadTest {

    private static Signer s;

    @BeforeClass
    public static void setUpBeforeClass() {
        s = new Signer(null);
    }

    @Test
    public void timestampTestInMilliseconds() throws Exception {
        SoapTestDocument soap = new SoapTestDocument();
        Document doc = soap.getDocument();
        soap.setTimestamp(true, true);
        Element t = soap.getTimestamp();
        assertTrue("Not Expired:\n" + domToString(t), s.verifyTimestamp(t));
        assertTrue("Not Expired:\n" + domToString(t), s.verifyTimestamp(doc));

        Payload o = new Payload(null, t);

        assertTrue("Not a Timestamp Element:\n" + domToString(t), o.isTimestamp());
        Element p = o.getPayloadElement();
        assertFalse("Expired: " + domToString(p), s.verifyTimestamp(p));
    }

    @Test
    public void timestampTest() throws Exception {
        SoapTestDocument soap = new SoapTestDocument();
        Document doc = soap.getDocument();
        soap.setTimestamp(true, false);
        Element t = soap.getTimestamp();
        assertTrue("Not Expired:\n" + domToString(t), s.verifyTimestamp(t));
        assertTrue("Not Expired:\n" + domToString(t), s.verifyTimestamp(doc));

        Payload o = new Payload(null, t);

        assertTrue("Not a Timestamp Element:\n" + domToString(t), o.isTimestamp());
        Element p = o.getPayloadElement();
        assertFalse("Expired: " + domToString(p), s.verifyTimestamp(p));
    }
}
