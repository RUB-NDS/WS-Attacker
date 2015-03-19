/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Juraj Somorovsky
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

package wsattacker.library.signatureFaking.helper;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import sun.security.x509.X509CertImpl;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class CertificateHandlerTest
    extends TestCase
{

    public static final String DIR = "src/test/resources/test-certificates";

    Logger log = Logger.getLogger( CertificateHandlerTest.class );

    private static String LOG_FILE = "logging.properties";

    /**
     * Create the test case
     * 
     * @param testName name of the test case
     */
    public CertificateHandlerTest( String testName )
    {
        super( testName );
        PropertyConfigurator.configure( LOG_FILE );
    }

    public static void testCertificateHandler()
        throws Exception
    {
        String certificate = FileReader.readFile( DIR + "/test-cert" );
        CertificateHandler ch = new CertificateHandler( certificate );
        ch.createFakedCertificate();
        X509CertImpl faked = ch.getFakedCertificate();

        CertificateFactory certFactory = CertificateFactory.getInstance( "X.509" );
        X509Certificate original =
            (X509Certificate) certFactory.generateCertificate( new ByteArrayInputStream(
                                                                                         Base64.decodeBase64( certificate ) ) );

        assertEquals( faked.getIssuerDN().getName(), original.getIssuerDN().getName() );
        assertEquals( faked.getSigAlgOID(), original.getSigAlgOID() );
        assertEquals( faked.getSubjectDN().getName(), original.getSubjectDN().getName() );
        faked.verify( faked.getPublicKey() );
    }
}
