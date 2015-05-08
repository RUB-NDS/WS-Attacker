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
package wsattacker.library.xmlencryptionattack.encryptedelements.key;

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
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElementTest;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 */
public class EncryptedKeyElementTest
{
    private static final Logger LOG = Logger.getLogger( EncryptedKeyElementTest.class );

    public EncryptedKeyElementTest()
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
        throws FileNotFoundException, XPathExpressionException, SAXException
    {
        EncryptedKeyElement encKey;
        EncryptedDataElement encDat;
        encKey = null;
        List<Element> encKeya = new ArrayList<Element>();
        try
        {
            Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_encData_signed.xml" );
            encKeya =
                (List<Element>) DomUtilities.evaluateXPath( doc,
                                                            "//*[local-name()='EncryptedKey' and namespace-uri()='"
                                                                + URI_NS_ENC + "']" );// DomUtilities.findChildren(doc.getParentNode(),"EncryptedData",
                                                                                      // null).get(0);
            for ( Element enc : encKeya )
            {
                encKey = new EncryptedKeyElement( enc );
            }

            assertEquals( "http://www.w3.org/2001/04/xmlenc#rsa-1_5", encKey.getEncryptionMethod() );
            assertEquals( "EncKeyId-urn:uuid:64DB4A7E53F67EF3F112142272504712", encKey.getIdValue() );
            // assertEquals(null,encKey.getType());
            // assertEquals(null,encKey.getMimeType());
            CipherValueElement ciph = (CipherValueElement) encKey.getCipherDataChild();
            String test = ciph.getEncryptedData();
            assertEquals( "Y1G4IvsVfHLHWEW89D7wC7wVYfks1/Q5JHru0NaZlDE89rRTIITZrjjS6ajcXcjNiRcQMbElYoG4tnfX"
                              + "OyqOYYPAWaBGXbQIQo+jFZq+hHfYt+j8YrOP8hg9uELzwtmPT7GAv1bFn+dEwEU6Ez5ZdCVH0cImWcf"
                              + "1fdezMkxvXcY=",
                          ciph.getEncryptedData() );
            assertEquals( 1, encKey.getReferenceElementList().size() );
            DataReferenceElement dataRef = (DataReferenceElement) encKey.getReferenceElementList().get( 0 );

            encDat = dataRef.getRefEncData();

            assertEquals( "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encDat.getEncryptionMethod() );
            assertEquals( "EncDataId-3808966", encDat.getIdValue() );
            assertEquals( "http://www.w3.org/2001/04/xmlenc#Content", encDat.getType() );
            assertEquals( "", encDat.getMimeType() );
            ciph = (CipherValueElement) encDat.getCipherDataChild();
            assertEquals( "lSDNH2zpu/R0039i85GoB93Sp2hg3rl20exTPccmN26YCt9rX54cbXFDwbZuIATYl52YPYHkHLK1WZP0JW+o7G8mjPAxiwBU"
                              + "K5hWwoOO1/I35wV7wJIvARS6CxS+IhHK3fnXsee8nLZulYaH1LDv7R+if2S1/v6YdhNodtZh2UqEZq0iHkr+GChEDwWpaiOUnyQ8m"
                              + "JS3hRq4GYnJEk4apQBIeuF8t64mNmY+ISlqNvQes2w5YVOsTUptmH4HPyVnfRuO/5tr7VNbh00myh0/309W8qgLCUlMJqN9nRa1v5+M"
                              + "X9t68pUgg92V1bV/46wE4xGDxyGgxk9asrJDvt+vNreMl5o3dOnvIaI8W5Dwpp/o7IkMtlFlT3aP7cETJ/Kb7VXLasQju2qPnSceXLJOW"
                              + "jLmMlqf9HraAmjaM/IbyEo=", ciph.getEncryptedData() );

        }
        catch ( IOException ex )
        {
            LOG.error( ex );
        }
    }

}
