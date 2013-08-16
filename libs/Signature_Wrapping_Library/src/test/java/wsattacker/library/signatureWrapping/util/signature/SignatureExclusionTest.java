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
package wsattacker.library.signatureWrapping.util.signature;

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import wsattacker.library.signatureWrapping.util.SoapTestDocument;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 *
 * @author christian
 */
public class SignatureExclusionTest {

    public SignatureExclusionTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void removeSignatureTest() throws Exception {
        Document preDoc = DomUtilities.readDocument("src/test/resources/saml_over_soap.xml");

        SignatureManager preManager = new SignatureManager();
        preManager.setDocument(preDoc);

        String xml = DomUtilities.domToString(preDoc);

        assertEquals(2, preManager.getSignatureElements().size());

        SignatureRemover r = new SignatureRemover(xml);

        String result = r.getXmlWithoutSignature();

        Document postDoc = DomUtilities.stringToDom(result);
        SignatureManager postManager = new SignatureManager();
        postManager.setDocument(postDoc);

        assertEquals(0, postManager.getSignatureElements().size());
    }

    public void noSignatureContainedTest() throws Exception {
        SoapTestDocument soap = new SoapTestDocument();
        String xml = DomUtilities.domToString(soap.getDocument());

        new SignatureRemover(xml);
    }

    public void invalidXML() throws Exception {
        new SignatureRemover("<a>");
    }

}
