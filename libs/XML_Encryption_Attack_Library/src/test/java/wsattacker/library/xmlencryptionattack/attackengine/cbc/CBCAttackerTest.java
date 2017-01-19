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
package wsattacker.library.xmlencryptionattack.attackengine.cbc;

import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.CBCAttacker;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import wsattacker.library.xmlencryptionattack.attackengine.TestCBCOracle;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class CBCAttackerTest
{

    private static Logger LOG = Logger.getLogger( CBCAttackerTest.class );

    /**
     * simple string
     */
    public static final String TEST_STRING = "abc";

    /**
     * complete xml string (fitting into one block)
     */
    public static final String TEST_XML_STRING = "<abc>fabcdef</abc>";

    /**
     * complete xml string (fitting into one block)
     */
    public static final String TEST_LONG_XML_STRING = "<xml><abcdef>fabcdef</abcdef>"
        + "<abcdef>fabcdef</abcdef><abcdef>fabcdef</abcdef><abcdef>fabcdef</abcdef>"
        + "<abcdef>fabcdef</abcdef><abcdef>fabcdef</abcdef><abcdef>fabcdef</abcdef>"
        + "<abcdef>fabcdef</abcdef><abcdef>fabcdef</abcdef><abcdef>fabcdef</abcdef>" + "</xml>";

    public CBCAttackerTest()
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
     * Test of executeAttack method, of class CBCAttacker.
     */
    @Test
    public void testSimpleString()
        throws Exception
    {
        TestCBCOracle oracle = new TestCBCOracle();
        byte[] original = TEST_STRING.getBytes();
        byte[] encryptedData = oracle.encryptTestData( original );

        CBCAttacker attacker = new CBCAttacker( encryptedData, oracle, 16 );
        byte[] dec = attacker.executeAttack();
        LOG.info( "Decrypted message: " + new String( dec ) );
        assertTrue( "The decrypted message was " + new String( dec ) + " and must be " + "equal to " + TEST_STRING,
                    Arrays.equals( dec, original ) );
    }

    /**
     * Test of executeAttack method, of class CBCAttacker.
     */
    @Test
    public void testXML()
        throws Exception
    {
        TestCBCOracle oracle = new TestCBCOracle();
        byte[] original = TEST_XML_STRING.getBytes();
        byte[] encryptedData = oracle.encryptTestData( original );

        CBCAttacker attacker = new CBCAttacker( encryptedData, oracle, 16 );
        byte[] dec = attacker.executeAttack();
        LOG.info( "Decrypted message: " + new String( dec ) );
        assertTrue( "The decrypted message was " + new String( dec ) + " and must be " + "equal to " + TEST_XML_STRING,
                    Arrays.equals( dec, original ) );
    }

    /**
     * Test of executeAttack method, of class CBCAttacker.
     */
    @Test
    public void testLongXML()
        throws Exception
    {
        TestCBCOracle oracle = new TestCBCOracle();
        byte[] original = TEST_LONG_XML_STRING.getBytes();
        byte[] encryptedData = oracle.encryptTestData( original );

        CBCAttacker attacker = new CBCAttacker( encryptedData, oracle, 16 );
        byte[] dec = attacker.executeAttack();
        LOG.info( "Decrypted message: " + new String( dec ) );
        assertTrue( "The decrypted message was " + new String( dec ) + " and must be " + "equal to "
            + TEST_LONG_XML_STRING, Arrays.equals( dec, original ) );
    }
}
