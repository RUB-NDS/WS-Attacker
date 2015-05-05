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
package wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import wsattacker.library.xmlencryptionattack.attackengine.CryptoAttackException;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;
import wsattacker.library.xmlencryptionattack.attackengine.Utility;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.PKCS1OracleRequest;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public final class PKCS1VectorGenerator
{

    private static Logger LOG = Logger.getLogger( PKCS1VectorGenerator.class );

    private static final int STATIC_VECTOR_SIZE = 11;

    /**
     * No instantiation needed, only one static method used
     */
    private PKCS1VectorGenerator()
    {
    }

    /**
     * Generates different encrypted PKCS1 vectors
     * 
     * @param cert certificate containing the RSA public key
     * @param algorithm symmetric key algorithm (it defines the length of the symmetric key and thus the position of
     *            0x00 in the PKCS1 padded structure)
     * @param setEncryptedData if true, the method generates for each encrypted key four different encrypted data
     *            vectors (valid and invalid encrypted data)
     * @return
     * @throws CryptoAttackException
     */
    public static OracleRequest[] generatePkcs1Vectors( Certificate cert, CryptoConstants.Algorithm algorithm,
                                                        boolean setEncryptedData )
        throws CryptoAttackException
    {
        return generatePkcs1Vectors( (RSAPublicKey) cert.getPublicKey(), algorithm, setEncryptedData );
    }

    /**
     * Generates different encrypted PKCS1 vectors
     * 
     * @param publicKey public key
     * @param algorithm symmetric key algorithm (it defines the length of the symmetric key and thus the position of
     *            0x00 in the PKCS1 padded structure)
     * @param setEncryptedData if true, the method generates for each encrypted key four different encrypted data
     *            vectors (valid and invalid encrypted data)
     * @return
     * @throws CryptoAttackException
     */
    public static OracleRequest[] generatePkcs1Vectors(RSAPublicKey publicKey,
			CryptoConstants.Algorithm algorithm, boolean setEncryptedData)
			throws CryptoAttackException {

		// generate key
		// we do not need secure random here
		Random random = new Random();
		byte[] keyBytes = new byte[algorithm.KEY_SIZE];
		random.nextBytes(keyBytes);
		LOG.debug("Generated a random symmetric key"
				+ Utility.bytesToHex(keyBytes));

		int rsaKeyLength = publicKey.getModulus().bitLength() / 8;

		// compute the number of all vectors that are being generated
		int vectorSize = STATIC_VECTOR_SIZE + rsaKeyLength - 2;

		// create plain padded keys
		byte[][] plainPaddedKeys = new byte[vectorSize][];
		plainPaddedKeys[0] = getEK_NoNullByte(rsaKeyLength, keyBytes);
		plainPaddedKeys[1] = getEK_NullByteInPadding(rsaKeyLength, keyBytes);
		plainPaddedKeys[2] = getEK_NullByteInPkcsPadding(rsaKeyLength, keyBytes);
		plainPaddedKeys[3] = getEK_SymmetricKeyOfSize16(rsaKeyLength, keyBytes);
		plainPaddedKeys[4] = getEK_SymmetricKeyOfSize24(rsaKeyLength, keyBytes);
		plainPaddedKeys[5] = getEK_SymmetricKeyOfSize32(rsaKeyLength, keyBytes);
		plainPaddedKeys[6] = getEK_SymmetricKeyOfSize40(rsaKeyLength, keyBytes);
		plainPaddedKeys[7] = getEK_SymmetricKeyOfSize8(rsaKeyLength, keyBytes);
		plainPaddedKeys[8] = getEK_WrongFirstByte(rsaKeyLength, keyBytes);
		plainPaddedKeys[9] = getEK_WrongSecondByte(rsaKeyLength, keyBytes);
		// correct key
		plainPaddedKeys[10] = getPaddedKey(rsaKeyLength, keyBytes);

		byte[][] additionalPaddedKeys = getEK_DifferentPositionsOf0x00(
				rsaKeyLength, keyBytes);
		System.arraycopy(additionalPaddedKeys, 0, plainPaddedKeys,
				STATIC_VECTOR_SIZE, additionalPaddedKeys.length);

		try {
			Security.addProvider(new BouncyCastleProvider());
			Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
			rsa.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[][] encryptedKeys = new byte[vectorSize][];
			// encrypt all the padded keys
			for (int i = 0; i < encryptedKeys.length; i++) {
				encryptedKeys[i] = rsa.doFinal(plainPaddedKeys[i]);
			}

			OracleRequest[] requests = null;
			if (setEncryptedData) {
				// return oracle requests containing pairs of encrypted keys and
				// encrypted data
				byte[][] encryptedData = getEncryptedSymmetricData(keyBytes,
						algorithm);
				requests = new OracleRequest[encryptedKeys.length
						* encryptedData.length];
				for (int i = 0; i < encryptedKeys.length; i++) {
					for (int j = 0; j < encryptedData.length; j++) {
						requests[i * (encryptedData.length) + j] = new PKCS1OracleRequest(
								encryptedKeys[i], encryptedData[j]);
					}
				}
			} else {
				// return oracle requests containing only different encrypted
				// keys
				requests = new OracleRequest[encryptedKeys.length];
				for (int i = 0; i < requests.length; i++) {
					requests[i] = new PKCS1OracleRequest(encryptedKeys[i]);
				}
			}
			return requests;

		} catch (BadPaddingException | IllegalBlockSizeException
				| InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException ex) {
			throw new CryptoAttackException(ex);
		}
	}

    /**
     * Generates encrypted data
     * 
     * @param key
     * @param algorithm
     * @return
     * @throws CryptoAttackException
     */
    private static byte[][] getEncryptedSymmetricData( byte[] key, CryptoConstants.Algorithm algorithm )
        throws CryptoAttackException
    {
        byte[][] encryptedData = new byte[4][];

        // valid xml text
        encryptedData[0] = Utility.encryptSymmetricData( "<test/>".getBytes(), key, algorithm );

        // invalid xml with opened tag
        encryptedData[1] = Utility.encryptSymmetricData( "<test>".getBytes(), key, algorithm );

        // empty string should generate a valid response in most of the
        // encryption libraries
        encryptedData[2] = Utility.encryptSymmetricData( "".getBytes(), key, algorithm );

        // invalid padding: generates encrypted data and then modifies the iv
        // by xoring the last byte of the initialization vector
        encryptedData[3] = Utility.encryptSymmetricData( "jlfsjl<js&".getBytes(), key, algorithm );
        encryptedData[3][algorithm.BLOCK_SIZE - 1] ^= 0x50;

        return encryptedData;
    }

    /**
     * Generates a validly padded message
     * 
     * @param rsaKeyLength rsa key length in bytes
     * @param symmetricKeyLength symmetric key length in bytes
     * @return
     */
    private static byte[] getPaddedKey( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = new byte[rsaKeyLength];
        // fill all the bytes with non-zero values
        Arrays.fill( key, (byte) 42 );
        // set the first byte to 0x00
        key[0] = 0x00;
        // set the second byte to 0x02
        key[1] = 0x02;
        // set the separating byte
        key[rsaKeyLength - symmetricKey.length - 1] = 0x00;
        // copy the symmetric key to the field
        System.arraycopy( symmetricKey, 0, key, rsaKeyLength - symmetricKey.length, symmetricKey.length );

        return key;
    }

    private static byte[] getEK_WrongFirstByte( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[0] = 23;
        LOG.debug( "Generated a PKCS1 padded message with a wrong first byte: " + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_WrongSecondByte( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[1] = 23;
        LOG.debug( "Generated a PKCS1 padded message with a wrong second byte: " + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_NoNullByte( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        for ( int i = 3; i < key.length; i++ )
        {
            if ( key[i] == 0x00 )
            {
                key[i] = 0x01;
            }
        }
        LOG.debug( "Generated a PKCS1 padded message with no separating byte: " + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_NullByteInPkcsPadding( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[3] = 0x00;
        LOG.debug( "Generated a PKCS1 padded message with a 0x00 byte in the PKCS1 padding: "
            + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_NullByteInPadding( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[11] = 0x00;
        LOG.debug( "Generated a PKCS1 padded message with a 0x00 byte in padding: " + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize40( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        key[rsaKeyLength - 40 - 1] = 0x00;
        LOG.debug( "Generated a PKCS1 padded symmetric key of size 40: " + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize32( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        for ( int i = 3; i < key.length; i++ )
        {
            if ( key[i] == 0x00 )
            {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 32 - 1] = 0x00;
        LOG.debug( "Generated a PKCS1 padded symmetric key of size 32: " + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize24( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        for ( int i = 3; i < key.length; i++ )
        {
            if ( key[i] == 0x00 )
            {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 24 - 1] = 0x00;
        LOG.debug( "Generated a PKCS1 padded symmetric key of size 24: " + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize16( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        for ( int i = 3; i < key.length; i++ )
        {
            if ( key[i] == 0x00 )
            {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 16 - 1] = 0x00;
        LOG.debug( "Generated a PKCS1 padded symmetric key of size 16: " + Utility.bytesToHex( key ) );
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize8( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
        for ( int i = 3; i < key.length; i++ )
        {
            if ( key[i] == 0x00 )
            {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 8 - 1] = 0x00;
        LOG.debug( "Generated a PKCS1 padded symmetric key of size 8: " + Utility.bytesToHex( key ) );
        return key;
    }

    /**
     * @param rsaKeyLength
     * @param symmetricKey
     * @return
     */
    // It is possible that this function generates vectors identical to
    // the vectors from the above functions (e.g. getEK_SymmetricKeyOfSizeX).
    // I will all the vectors here
    // (it is possible that we need some fine-tuning in the future, then these
    // vectors are useful)
    private static byte[][] getEK_DifferentPositionsOf0x00( int rsaKeyLength, byte[] symmetricKey )
    {
        byte[][] result = new byte[rsaKeyLength - 2][];
        for ( int i = 2; i < rsaKeyLength; i++ )
        {
            // generate padded key
            byte[] key = getPaddedKey( rsaKeyLength, symmetricKey );
            // remove 0x00
            for ( int j = 3; j < key.length; j++ )
            {
                if ( key[j] == 0x00 )
                {
                    key[j] = 0x01;
                }
            }
            result[i - 2] = key;
            // insert 0x00 to an incorrect position
            result[i - 2][i] = 0x00;
        }

        return result;
    }
}
