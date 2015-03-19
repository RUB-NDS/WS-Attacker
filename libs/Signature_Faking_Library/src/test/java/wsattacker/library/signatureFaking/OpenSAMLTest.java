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
package wsattacker.library.signatureFaking;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.ReplayCacheFactory;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLBrowserProfile;
import org.opensaml.SAMLBrowserProfileFactory;
import org.opensaml.SAMLIdentifier;
import org.opensaml.SAMLIdentifierFactory;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLSubject;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class OpenSAMLTest
    extends TestCase
{

    private String path = "src/test/resources/crt/test.jks";

    private String alias = "mykey";

    private char[] password = "opensaml".toCharArray();

    private KeyStore ks = null;

    Logger log = Logger.getLogger( OpenSAMLTest.class );

    private static String LOG_FILE = "logging.properties";

    /**
     * Create the test case
     * 
     * @param testName name of the test case
     */
    public OpenSAMLTest( String testName )
        throws KeyStoreException, FileNotFoundException, CertificateException, IOException, NoSuchAlgorithmException
    {
        super( testName );
        PropertyConfigurator.configure( LOG_FILE );
        ks = KeyStore.getInstance( "JKS" );
        InputStream is = new FileInputStream( new File( path ) );
        try
        {
            ks.load( is, password );
        }
        finally
        {
            if ( is != null )
            {
                is.close();
            }
        }
    }

    public String generateSAML()
        throws Exception
    {
        SAMLBrowserProfile profile = SAMLBrowserProfileFactory.getInstance();
        SAMLIdentifier idgen = SAMLIdentifierFactory.getInstance();
        SAMLResponse r = new SAMLResponse();
        SAMLAssertion a = new SAMLAssertion();
        SAMLAuthenticationStatement s = new SAMLAuthenticationStatement();
        SAMLSubject subject =
            new SAMLSubject( new SAMLNameIdentifier( "foo", null, null ),
                             Collections.singleton( SAMLSubject.CONF_BEARER ), null, null );
        s.setSubject( subject );
        s.setAuthInstant( new Date() );
        s.setAuthMethod( SAMLAuthenticationStatement.AuthenticationMethod_Password );
        a.addStatement( s );
        a.setId( idgen.getIdentifier() );
        a.setIssuer( "http://www.opensaml.org" );
        a.setNotBefore( new Date() );
        a.setNotOnOrAfter( new Date( System.currentTimeMillis() + 360000 ) );
        a.addCondition( new SAMLAudienceRestrictionCondition( Collections.singleton( "http://www.opensaml.org" ) ) );
        r.addAssertion( a );
        r.setId( idgen.getIdentifier() );
        r.setRecipient( "http://www.opensaml.org" );

        r.sign( XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, ks.getKey( alias, password ),
                Arrays.asList( ks.getCertificateChain( alias ) ) );
        return r.toString();
    }

    public boolean validateSAML( String message )
        throws Exception
    {
        SAMLBrowserProfile profile = SAMLBrowserProfileFactory.getInstance();
        SAMLBrowserProfile.BrowserProfileRequest request = new SAMLBrowserProfile.BrowserProfileRequest();
        request.SAMLResponse = new String( Base64.encodeBase64( message.getBytes() ) );
        SAMLBrowserProfile.BrowserProfileResponse response =
            profile.receive( null, request, "http://www.opensaml.org", ReplayCacheFactory.getInstance(), null, 1 );

        try
        {
            response.response.verify();
        }
        catch ( Exception e )
        {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public void testFakingLib()
        throws Exception
    {
        String message = this.generateSAML();
        log.debug( "Original Message: \r\n" );
        log.debug( message );
        assertTrue( this.validateSAML( message ) );

        SignatureFakingOracle sfo = new SignatureFakingOracle( message );
        sfo.fakeSignatures();
        String fakedMessage = sfo.getDocument();
        log.debug( "Faked Message: \r\n" );
        log.debug( fakedMessage );
        assertTrue( this.validateSAML( fakedMessage ) );
    }
}
