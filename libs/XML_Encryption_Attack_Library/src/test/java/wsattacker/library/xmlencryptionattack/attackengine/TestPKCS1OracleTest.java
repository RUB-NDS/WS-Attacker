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

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.PKCS1VectorGenerator;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TestPKCS1OracleTest
{

    public TestPKCS1OracleTest()
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
     * Test of the PKCS1 Oracle with some queries fromPKCS1VectorGeneratorrator
     */
    @Test
    public void testSomeMessagesFromGenerator()
        throws Exception
    {
        TestPKCS1Oracle oracle = new TestPKCS1Oracle();

        OracleRequest[] requests =
            PKCS1VectorGenerator.generatePkcs1Vectors( oracle.getPublicKey(), CryptoConstants.Algorithm.CBC_AES128,
                                                       false );

        OracleResponse response;

        // NoNullByte
        response = oracle.queryOracle( requests[0] );
        assertTrue( "The message starts with 0x00 0x02, thus the message should " + "be valid",
                    response.getResult() == OracleResponse.Result.VALID );

        // WrongFirstByte
        response = oracle.queryOracle( requests[8] );
        assertTrue( "The first message byte was changed, thus the message should " + "be invalid",
                    response.getResult() == OracleResponse.Result.INVALID );

        // WrongSecondByte
        response = oracle.queryOracle( requests[9] );
        assertTrue( "The second message byte was changed, thus the message should " + "be invalid",
                    response.getResult() == OracleResponse.Result.INVALID );
    }
}
