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

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.log4j.Logger;
import org.xml.sax.InputSource;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.CBCAttacker;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.FindIVMethodProperties;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse.Result;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TestCBCOracle
    extends AOracle
{

    Logger LOG = Logger.getLogger( TestCBCOracle.class );

    private final byte[] key;

    private final CryptoConstants.Algorithm algorithm;

    private FindIVMethodProperties.Type type;

    public TestCBCOracle( FindIVMethodProperties.Type type )
    {
        Random sr = new Random();
        algorithm = CryptoConstants.Algorithm.CBC_AES128;
        key = new byte[algorithm.KEY_SIZE];
        sr.nextBytes( key );
        this.type = type;
    }

    public TestCBCOracle()
    {
        this( FindIVMethodProperties.Type.DEFAULT );
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

        byte[] iv = Arrays.copyOf( request.getEncryptedData(), algorithm.BLOCK_SIZE );
        byte[] encrypted =
            Arrays.copyOfRange( request.getEncryptedData(), algorithm.BLOCK_SIZE, request.getEncryptedData().length );

        try
        {
            SecretKeySpec skeySpec = new SecretKeySpec( key, algorithm.KEY_SPEC_NAME );
            Cipher decryptor = Cipher.getInstance( algorithm.JAVA_NAME );
            IvParameterSpec ivParameterSpec = new IvParameterSpec( iv );

            decryptor.init( Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec );
            byte[] paddedResult = decryptor.doFinal( encrypted );

            // check padding
            if ( paddedResult[paddedResult.length - 1] == 0 || paddedResult[paddedResult.length - 1] > 16 )
            {
                resp.setResult( Result.INVALID );
                return resp;
            }
            byte[] result =
                Arrays.copyOf( paddedResult, ( paddedResult.length - paddedResult[paddedResult.length - 1] ) );
            LOG.debug( "Currently Decrypted a string of length " + result.length + " bytes: " + new String( result ) );

            // in a case we are working with datapower, this machine does not parse messages of null length
            if ( type == FindIVMethodProperties.Type.IBM_DATAPOWER )
            {
                if ( result.length == 0 )
                {
                    LOG.debug( "The decrypted Result is of null length, IBM Datapower responds with false" );
                    resp.setResult( Result.INVALID );
                    return resp;
                }
            }

            // This is how the xml encryption libraries typically process the
            // decrypted content. They first put the decrypted bytes into a
            // dummy
            // element (with all the namespaces defined). Afterwards, the whole
            // content is parsed. This has the following advantages: the parser
            // can parse simple strings and it can easilly be filled with the
            // namespaces used in the decrypted document.
            String start = "<xml>";
            String end = "</xml>";

            byte[] wrappedResult = new byte[start.length() + result.length + end.length()];

            System.arraycopy( start.getBytes(), 0, wrappedResult, 0, start.length() );
            System.arraycopy( result, 0, wrappedResult, start.length(), result.length );
            System.arraycopy( end.getBytes(), 0, wrappedResult, start.length() + result.length, end.length() );

            LOG.debug( "Wrapped result: " + new String( wrappedResult ) );

            // Get the DOM Builder Factory
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // Get the DOM Builder
            DocumentBuilder builder = factory.newDocumentBuilder();

            // Load and Parse the XML document
            // document contains the complete XML as a Tree.
            InputSource is = new InputSource( new ByteArrayInputStream( wrappedResult ) );
            builder.parse( is );

            resp.setResult( Result.VALID );
            return resp;
        }
        catch ( Exception e )
        {
            LOG.debug( "error happend", e );
            resp.setResult( Result.INVALID );
            return resp;
        }
    }

    public byte[] encryptTestData( byte[] plainBytes )
        throws Exception
    {
        return Utility.encryptSymmetricData( plainBytes, key, algorithm );
    }

    @Override
    public void setResponseValidity( OracleResponse response, OracleResponse.Result result )
    {
        throw new UnsupportedOperationException( "Not supported yet." ); // To change body of generated methods, choose
        // Tools | Templates.
    }

    public void setOracleType( FindIVMethodProperties.Type type )
    {
        this.type = type;
    }
}
