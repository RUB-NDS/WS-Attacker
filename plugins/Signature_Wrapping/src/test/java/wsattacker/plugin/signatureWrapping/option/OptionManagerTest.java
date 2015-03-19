/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2011 Christian Mainka
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
package wsattacker.plugin.signatureWrapping.option;

import java.io.*;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.xml.sax.SAXException;

/**
 * @author christian
 */
public class OptionManagerTest
{

    private static final Logger LOG = Logger.getLogger( OptionManagerTest.class );

    private static final String SIMPLE_SIGNED = "src/test/resources/Signed_Request.xml";

    public OptionManagerTest()
    {
    }

    @Test
    public void testSimpleSignedRequest()
        throws FileNotFoundException, IOException, SAXException
    {
        // LOG.info("Options for testSimpleSignedRequest");
        // OptionManager optionManager = OptionManager.getInstance();
        // SignatureManager signatureManager = new SignatureManager();
        //
        // optionManager.setSignatureManager(signatureManager);
        //
        // Document signed_request = DomUtilities.readDocument(SIMPLE_SIGNED);
        // assertNotNull(signed_request);
        //
        // optionManager.currentRequestContentChanged(DomUtilities.domToString(signed_request),
        // "");
        //
        // assertEquals(1, signatureManager.getPayloads().size());
        //
        // Document usedXML = signatureManager.getDocument();
        // assertTrue(signed_request.isEqualNode(usedXML));
    }
}
