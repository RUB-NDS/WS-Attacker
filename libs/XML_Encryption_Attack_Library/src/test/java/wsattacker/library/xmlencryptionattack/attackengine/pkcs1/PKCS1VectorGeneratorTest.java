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

import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.PKCS1VectorGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import wsattacker.library.xmlencryptionattack.attackengine.Utility;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants.Algorithm;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class PKCS1VectorGeneratorTest
{

    Logger LOG = Logger.getLogger( PKCS1VectorGeneratorTest.class );

    public PKCS1VectorGeneratorTest()
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
     * Test of generatePkcs1Vectors method, of class PKCS1VectorGenerator.
     */
    @Test
    public void testGeneratePkcs1VectorsWithoutEncryptedData()
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance( "RSA" );
        keyGen.initialize( 1024 );
        KeyPair keyPair = keyGen.genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        final Algorithm algorithm = CryptoConstants.Algorithm.CBC_AES128;
        OracleRequest[] result = PKCS1VectorGenerator.generatePkcs1Vectors( (RSAPublicKey) publicKey, algorithm, false );
        assertTrue( "This method should generate " + 137 + " vectors", result.length == 137 );

        result = PKCS1VectorGenerator.generatePkcs1Vectors( (RSAPublicKey) publicKey, algorithm, true );
        assertTrue( "This method should generate " + ( 137 * 4 ) + " vectors, but " + "generated " + result.length,
                    result.length == ( 137 * 4 ) );

        // first generated key should have no null byte and be 127 bytes long
        byte[] key = result[0].getEncryptedKey();
        Cipher c = Cipher.getInstance( "RSA/None/NoPadding" );
        c.init( Cipher.DECRYPT_MODE, keyPair.getPrivate() );
        byte[] decKey = c.doFinal( key );
        LOG.debug( "decrypted key: " + Utility.bytesToHex( decKey ) );
        assertTrue( "The key should consist of 127 bytes", decKey.length == 127 );
        assertTrue( "The key must not contain a 0x00 byte", ( Arrays.binarySearch( decKey, 0, 112, (byte) 0 ) == -1 ) );

        // 11th generated encrypted key should be correctly padded (we compute
        // 10*4 as we have 4 encrypted data vectors for each encrypted key)
        key = result[40].getEncryptedKey();
        c = Cipher.getInstance( "RSA/None/PKCS1Padding" );
        c.init( Cipher.DECRYPT_MODE, keyPair.getPrivate() );
        decKey = c.doFinal( key );
        LOG.info( "decrypted key: " + Utility.bytesToHex( decKey ) );

        byte[] iv = Arrays.copyOf( result[40].getEncryptedData(), algorithm.BLOCK_SIZE );
        byte[] encrypted =
            Arrays.copyOfRange( result[40].getEncryptedData(), algorithm.BLOCK_SIZE,
                                result[40].getEncryptedData().length );

        SecretKeySpec skeySpec = new SecretKeySpec( decKey, algorithm.KEY_SPEC_NAME );
        Cipher decryptor = Cipher.getInstance( algorithm.JAVA_NAME );
        IvParameterSpec ivParameterSpec = new IvParameterSpec( iv );

        decryptor.init( Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec );
        byte[] decrypted = decryptor.doFinal( encrypted );

        LOG.debug( "decrypted data: " + Utility.bytesToHex( decrypted ) );
        assertTrue( "The decrypted data must start with <test", ( new String( decrypted, 0, 6 ) ).startsWith( "<test" ) );
    }
}
