/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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
package wsattacker.library.xmlencryptionattack.encryptedelements.data;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.xmlencryptionattack.encryptedelements.CipherValueElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 */
public class EncryptedDataElementTest
{
	private static final Logger LOG = Logger.getLogger( EncryptedDataElementTest.class );

    public EncryptedDataElementTest()
    {
    }

    @BeforeClass
    public static void setUpClass()
    {
    }

    @AfterClass
    public static void tearDownClass()
    {
    }

    @Before
    public void setUp()
    {
    }

    @After
    public void tearDown()
    {
    }

    @Test
    public void testSomeMethod()
        throws FileNotFoundException, SAXException, XPathExpressionException
    {
        // List<Element> encData;
        EncryptedDataElement encDat;
        encDat = null;
        List<Element> encData = new ArrayList<Element>();
        try
        {
            Document doc = DomUtilities.readDocument( "src/test/resources/case_encData_only.xml" );
            encData =
                (List<Element>) DomUtilities.evaluateXPath( doc,
                                                            "//*[local-name()='EncryptedData' and namespace-uri()='"
                                                                + URI_NS_ENC + "']" );// DomUtilities.findChildren(doc.getParentNode(),"EncryptedData",
                                                                                      // null).get(0);
            for ( Element enc : encData )
            {
                // log().trace("Found Signature Element " +
                // DomUtilities.getFastXPath(signature));
                encDat = new EncryptedDataElement( enc );
            }
            assertEquals( "http://www.w3.org/2001/04/xmlenc#aes128-cbc", encDat.getEncryptionMethod() );
            assertEquals( "ED-1", encDat.getIdValue() );
            assertEquals( "http://www.w3.org/2001/04/xmlenc#Content", encDat.getType() );
            // assertEquals(null,encDat.getMimeType());
            CipherValueElement ciph = (CipherValueElement) encDat.getCipherDataChild();
            assertEquals( "UM2LlzEpNjpgdupv3Kd6ELb4q2HxR4ligF9WOIIbXMU=", ciph.getEncryptedData() );
        }
        catch ( IOException ex )
        {
            LOG.error(ex);
        }
    }

}
