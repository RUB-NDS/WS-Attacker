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
package wsattacker.library.xmlencryptionattack.attackengine;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.log4j.Logger;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class Utility
{

    private static Logger LOG = Logger.getLogger( Utility.class );

    /**
     * Valid Hex Chars.
     */
    private final static char[] HEXCHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
        'f' };

    /**
     * Converts a byte array into its hex string representation.
     * 
     * @param bytes Bytes to convert
     * @return Hex string of delivered byte array
     */
    public static String bytesToHex( final byte[] bytes )
    {
        StringBuilder builder = new StringBuilder( bytes.length * 2 );

        for ( int i = 0; i < bytes.length; i++ )
        {
            // unsigned right shift of the MSBs
            builder.append( HEXCHARS[( bytes[i] & 0xff ) >>> 4] );
            // handling the LSBs
            builder.append( HEXCHARS[bytes[i] & 0xf] );
            builder.append( ' ' );
        }

        return builder.toString();
    }

    public static byte[] encryptSymmetricData(byte[] plaintext, byte[] key,
			CryptoConstants.Algorithm algorithm) throws CryptoAttackException {
		int blocks = (plaintext.length / algorithm.BLOCK_SIZE) + 1;
		byte[] paddedText = new byte[blocks * algorithm.BLOCK_SIZE];
		Random r = new Random();
		r.nextBytes(paddedText);
		System.arraycopy(plaintext, 0, paddedText, 0, plaintext.length);
		int paddingByte = paddedText.length - plaintext.length;
		paddedText[paddedText.length - 1] = (byte) paddingByte;

		LOG.debug("padding byte: " + paddingByte);

		SecretKeySpec skeySpec = new SecretKeySpec(key, algorithm.KEY_SPEC_NAME);
		try {
			Cipher encryptor = Cipher.getInstance(algorithm.JAVA_NAME);

			byte[] iv = new byte[encryptor.getBlockSize()];
			r.nextBytes(iv);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

			encryptor.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
			byte[] result = new byte[iv.length + paddedText.length];
			byte[] encrypted = encryptor.doFinal(paddedText);
			System.arraycopy(iv, 0, result, 0, iv.length);
			System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
			return result;
		} catch (BadPaddingException | IllegalBlockSizeException
				| InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
			throw new CryptoAttackException(ex);
		}
	}

    public static final String[] getAttackStringPartsFromDoc( int dataSize, AbstractEncryptionElement tmpEncData,
                                                              Document attackDocument )
    {
        String[] attackParts = new String[2];
        Random r = new Random();
        byte[] b = new byte[dataSize * 2];
        r.nextBytes( b );
        String rndPay = Base64.encodeBytes( b );
        tmpEncData.getCipherDataChild().setEncryptedData( rndPay );
        String attackString = domToString( attackDocument );
        int indexOfPay = attackString.indexOf( rndPay );
        attackParts[0] = attackString.subSequence( 0, indexOfPay ).toString();
        attackParts[1] = attackString.subSequence( indexOfPay + rndPay.length(), attackString.length() ).toString();
        return attackParts;
    }

    // reads a file with Base64 encoded certificates,
    // beginning by -----BEGIN CERTIFICATE-----,
    // and bounded at the end by -----END CERTIFICATE-----.
    public static PublicKey getPubKeyFromCert( File certFile )
        throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, CertificateException,
        FileNotFoundException, IOException
    {
        FileInputStream fis = new FileInputStream( certFile );
        BufferedInputStream bis = new BufferedInputStream( fis );
        CertificateFactory cf = CertificateFactory.getInstance( "X.509" );
        Certificate cert = (X509Certificate) cf.generateCertificate( bis );
        return cert.getPublicKey();
    }

    // DER Format Public Key
    public static PublicKey getPubKeyFromKeyFile( File pubKeyFile )
        throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, CertificateException,
        FileNotFoundException, IOException
    {
        FileInputStream fis = new FileInputStream( pubKeyFile );
        byte[] keyBytes;
        try (DataInputStream dis = new DataInputStream( fis )) 
        {
            keyBytes = new byte[(int) pubKeyFile.length()];
            dis.readFully( keyBytes );
            dis.close();
        }

        X509EncodedKeySpec spec = new X509EncodedKeySpec( keyBytes );
        KeyFactory kf = KeyFactory.getInstance( "RSA" );
        return kf.generatePublic( spec );
    }
}
