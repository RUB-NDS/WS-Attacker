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
 * A very simple plaintext oracle responding with 1 (if the message starts with 0x00 0x02) or 0 (otherwise)
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TestPKCS1PlaintextOracle
    extends AOracle
{

    Logger LOG = Logger.getLogger( TestPKCS1PlaintextOracle.class );

    public TestPKCS1PlaintextOracle( RSAPublicKey publicKey )
        throws CryptoAttackException
    {
        this.m_PublicKey = publicKey;
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

        int keyLength = m_PublicKey.getModulus().bitLength() / 8;

        byte[] test = request.getEncryptedKey();
        if ( ( ( test.length == keyLength - 1 ) && ( test[0] == 0x02 ) )
            || ( ( test.length == keyLength ) && test[0] == 0x00 && test[1] == 0x02 ) )
        {
            resp.setResult( Result.VALID );
            for ( int i = 1; i < 10; i++ )
            {
                if ( test[i] == 0 )
                {
                    resp.setResult( Result.INVALID );
                }
            }
        }
        else
        {
            resp.setResult( Result.INVALID );
        }
        // if (resp.getResult() == Result.VALID) {
        // System.out.println("Valid: " + Utility.bytesToHex(test));
        // }

        return resp;
    }

    @Override
    public void setResponseValidity( OracleResponse response, OracleResponse.Result result )
    {
        throw new UnsupportedOperationException( "Not supported yet." ); // To change body of generated methods, choose
        // Tools | Templates.
    }
}
