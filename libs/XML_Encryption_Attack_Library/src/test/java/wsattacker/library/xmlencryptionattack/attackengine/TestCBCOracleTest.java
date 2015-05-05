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

import static org.junit.Assert.*;
import org.junit.Test;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.CBCAttacker;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.FindIVMethodProperties;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TestCBCOracleTest
{

    public static final String TEST_STRING = "abc";

    public static final String TEST_XML_STRING = "<abc>abc</abc>";

    public static final String TEST_INVALID_XML = "<ab>abc</abc>";

    public static final String TEST_AMPERSAND = "abc&abc";

    public static final String TEST_NULL = "";

    /**
     * Test of the TestCBCOracle with simple XML
     */
    @Test
    public void testSimpleXML()
        throws Exception
    {
        TestCBCOracle to = new TestCBCOracle();
        byte[] x = to.encryptTestData( TEST_XML_STRING.getBytes() );
        OracleRequest req = new OracleRequest();
        req.setEncryptedData( x );
        OracleResponse resp = to.queryOracle( req );

        assertTrue( "a simple xml must be parsed correctly", resp.getResult() == OracleResponse.Result.VALID );
    }

    /**
     * Test of the TestCBCOracle with a short string
     */
    @Test
    public void testSimpleString()
        throws Exception
    {
        TestCBCOracle to = new TestCBCOracle();
        byte[] x = to.encryptTestData( TEST_STRING.getBytes() );
        OracleRequest req = new OracleRequest();
        req.setEncryptedData( x );
        OracleResponse resp = to.queryOracle( req );

        assertTrue( "a simple string must be parsed correctly", resp.getResult() == OracleResponse.Result.VALID );
    }

    /**
     * Test of the TestCBCOracle with an empty string
     */
    @Test
    public void testEmptyString()
        throws Exception
    {
        TestCBCOracle to = new TestCBCOracle();
        byte[] x = to.encryptTestData( "".getBytes() );
        OracleRequest req = new OracleRequest();
        req.setEncryptedData( x );
        OracleResponse resp = to.queryOracle( req );

        assertTrue( "an empty string must be parsed correctly", resp.getResult() == OracleResponse.Result.VALID );
    }

    /**
     * Test of the TestCBCOracle with an invalid xml string
     */
    @Test
    public void testInalidXML()
        throws Exception
    {
        TestCBCOracle to = new TestCBCOracle();
        byte[] x = to.encryptTestData( TEST_INVALID_XML.getBytes() );
        OracleRequest req = new OracleRequest();
        req.setEncryptedData( x );
        OracleResponse resp = to.queryOracle( req );

        assertTrue( "an invalid xml string cannot be parsed correctly",
                    resp.getResult() == OracleResponse.Result.INVALID );
    }

    /**
     * Test of the TestCBCOracle with an invalid string since it contains an ampersand
     */
    @Test
    public void testAmpersand()
        throws Exception
    {
        TestCBCOracle to = new TestCBCOracle();
        byte[] x = to.encryptTestData( TEST_AMPERSAND.getBytes() );
        OracleRequest req = new OracleRequest();
        req.setEncryptedData( x );
        OracleResponse resp = to.queryOracle( req );

        assertTrue( "a string containg an & cannot be parsed correctly",
                    resp.getResult() == OracleResponse.Result.INVALID );
    }

    /**
     * Test of the TestCBCOracle with a Null String. Should be different for Datapower and others
     */
    @Test
    public void testNullString()
        throws Exception
    {
        TestCBCOracle to = new TestCBCOracle();
        byte[] x = to.encryptTestData( TEST_NULL.getBytes() );
        OracleRequest req = new OracleRequest();
        req.setEncryptedData( x );
        OracleResponse resp = to.queryOracle( req );

        assertTrue( "a string of null length is parsed correctly by default",
                    resp.getResult() == OracleResponse.Result.VALID );

        to = new TestCBCOracle( FindIVMethodProperties.Type.IBM_DATAPOWER );
        resp = to.queryOracle( req );
        assertTrue( "a string of null length cannot be parsed by a datapower",
                    resp.getResult() == OracleResponse.Result.INVALID );
    }
}
