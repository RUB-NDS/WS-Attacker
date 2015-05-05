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

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse.Result;

/**
 * A very simple oracle decrypting a message and responding with 1 (if the message starts with 0x00 0x02) or 0
 * (otherwise)
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TestPKCS1Oracle
    extends AOracle
{

    Logger LOG = Logger.getLogger( TestPKCS1Oracle.class );

    private static final int KEY_SIZE = 128;

    private byte[] key;

    private Cipher cipher;

    public TestPKCS1Oracle() throws CryptoAttackException {
        Random sr = new Random();
        key = new byte[KEY_SIZE];
        sr.nextBytes(key);

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.genKeyPair();
            this.m_PublicKey = (RSAPublicKey) keyPair.getPublic();

            cipher = Cipher.getInstance("RSA/None/NoPadding",
                    new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            LOG.info(e);
            throw new CryptoAttackException();
        }
    }

    @Override
    public OracleResponse[] sendRequests( OracleRequest[] request )
    {
        throw new UnsupportedOperationException( "Not supported yet." );
    }

    @Override
    public OracleResponse queryOracle( OracleRequest request )
    {
        numberOfQueries++;
        OracleResponse resp = new OracleResponse();

        try
        {
            byte[] encKey = request.getEncryptedKey();

            byte[] decKey = cipher.doFinal( encKey );

            // the decrypted message starts with 0x00 0x02 (the first byte is
            // typically removed from the decrypted message if it is 0x00)
            if ( ( decKey.length == KEY_SIZE - 1 ) && decKey[0] == 0x02 )
            {
                resp.setResult( Result.VALID );
            }
            else
            {
                resp.setResult( Result.INVALID );
            }
            return resp;
        }
        catch ( Exception e )
        {
            LOG.info( "error happend", e );
            resp.setResult( Result.INVALID );
            return resp;
        }
    }

    @Override
    public void setResponseValidity( OracleResponse response, OracleResponse.Result result )
    {
        throw new UnsupportedOperationException( "Not supported yet." ); // To change body of generated methods, choose
                                                                         // Tools | Templates.
    }
}
