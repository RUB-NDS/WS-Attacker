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
package wsattacker.library.xmlencryptionattack.attackengine.pkcs1;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;
import javax.crypto.Cipher;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import wsattacker.library.xmlencryptionattack.attackengine.TestPKCS1Oracle;
import wsattacker.library.xmlencryptionattack.attackengine.TestPKCS1PlaintextOracle;
import wsattacker.library.xmlencryptionattack.attackengine.Utility;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.BleichenbacherAttacker;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class BleichenbacherAttackerTest
{

    Logger LOG = Logger.getLogger( BleichenbacherAttackerTest.class );

    private static final byte[] plainPKCS1024 = new byte[] { (byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0xc0,
        (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba,
        (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff,
        (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe,
        (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0,
        (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba,
        (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff,
        (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe,
        (byte) 0xc0, (byte) 0xff, (byte) 0xee, (byte) 0xba, (byte) 0xbe, (byte) 0xc0, (byte) 0xff, (byte) 0xee,
        (byte) 0xba, (byte) 0xbe, (byte) 0x00, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x03,
        (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
        (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
        (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b,
        (byte) 0x1c, (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23,
        (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27, (byte) 0x28, (byte) 0x29, (byte) 0x2a, (byte) 0x2b,
        (byte) 0x2c, (byte) 0x2d, (byte) 0x2e };

    public BleichenbacherAttackerTest()
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

    /**
     * Test of attack method, of class BleichenbacherAttacker.
     */
    @Test
    @Ignore
    public void testAttack()
        throws Exception
    {

        // create an oracle and encrypt the message

        TestPKCS1Oracle oracle = new TestPKCS1Oracle();
        Cipher cipher = Cipher.getInstance( "RSA/None/NoPadding", new BouncyCastleProvider() );
        cipher.init( Cipher.ENCRYPT_MODE, oracle.getPublicKey() );
        byte[] encKey = cipher.doFinal( plainPKCS1024 );

        BleichenbacherAttacker instance = new BleichenbacherAttacker( encKey, oracle, true );
        byte[] result = instance.executeAttack();

        LOG.info( "The decrypted message was found after " + oracle.getNumberOfQueries() + " queries:\n "
            + Utility.bytesToHex( result ) );
        oracle.getNumberOfQueries();
        assertArrayEquals( "The decrypted message must be equal to the encrypted " + "one", plainPKCS1024, result );

    }

    @Test
    @Ignore
    public void testAttackPerformance()
        throws Exception
    {

        System.out.println( "Bleichenbacher Attack test with a constant message" );

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance( "RSA" );
        keyGen.initialize( 1024 );
        KeyPair keyPair = keyGen.genKeyPair();
        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

        TestPKCS1PlaintextOracle oracle = new TestPKCS1PlaintextOracle( pubKey );

        int blockSize = pubKey.getModulus().bitLength() / 8;
        byte[] dummyKey = new byte[blockSize];
        Random r = new Random();
        r.nextBytes( dummyKey );
        dummyKey[0] = 0;
        dummyKey[1] = 2;

        BleichenbacherPlaintextAttacker instance = new BleichenbacherPlaintextAttacker( dummyKey, oracle );
        byte[] result = instance.executeAttack();

        LOG.info( "The decrypted message was found after " + oracle.getNumberOfQueries() + " queries:\n "
            + Utility.bytesToHex( result ) );

        Cipher cipher = Cipher.getInstance( "RSA/None/NoPadding", new BouncyCastleProvider() );
        cipher.init( Cipher.ENCRYPT_MODE, oracle.getPublicKey() );
        byte[] encKey = cipher.doFinal( dummyKey );

        LOG.info( "Encrypted Key in Base64: " + new String( Base64.encode( encKey ) ) );

    }

    private static X509Certificate loadCert( String fileName )
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        CertificateFactory factory = CertificateFactory.getInstance( "X.509" );
        X509Certificate certificate = (X509Certificate) factory.generateCertificate( new FileInputStream( fileName ) );
        return certificate;
    }
}
