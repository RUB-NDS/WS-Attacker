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

import java.util.Arrays;
import static org.junit.Assert.*;
import org.junit.Test;
import wsattacker.library.xmlencryptionattack.attackengine.TestCBCOracle;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.CBCAttacker;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.FindIVMethodProperties;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.FindIVMethodSimple;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class FindIVMethodSimpleTest
{

    /**
     * simple string
     */
    public static final String TEST_STRING = "abc";

    /**
     * incomplete xml string (fitting into one block)
     */
    public static final String TEST_XML_STRING = "<abc>fabcdef</ab";

    public FindIVMethodSimpleTest()
    {
    }

    /**
     * Test of executeAttack method, of class FindIVMethod.
     */
    @Test
    public void testSimpleString()
        throws Exception
    {
        System.out.println( "Execute Attack in the findIV Method" );
        TestCBCOracle oracle = new TestCBCOracle();
        byte[] original = TEST_STRING.getBytes();
        byte[] encryptedData = oracle.encryptTestData( original );
        byte[] iv = Arrays.copyOf( encryptedData, 16 );
        byte[] c1 = Arrays.copyOfRange( encryptedData, 16, 32 );

        System.out.println( "Default oracle" );
        FindIVMethodSimple fim = new FindIVMethodSimple( oracle, iv, c1, true );
        byte[] dec = fim.executeAttack();
        assertTrue( "The decrypted message was " + new String( dec ) + " and must be " + "equal to " + TEST_STRING,
                    Arrays.equals( dec, original ) );

        oracle.setOracleType( FindIVMethodProperties.Type.IBM_DATAPOWER );
        fim = new FindIVMethodSimple( oracle, iv, c1, true );
        dec = fim.executeAttack();
        assertTrue( "The decrypted message was " + new String( dec ) + " and must be " + "equal to " + TEST_STRING,
                    Arrays.equals( dec, original ) );
    }

    /**
     * Test of executeAttack method, of class FindIVMethod. It decrypts an incomplete XML string fitting into one block
     * (the method is not able to process xml data fitting into one block!)
     */
    @Test
    public void testXMLString()
        throws Exception
    {
        System.out.println( "Execute Attack in the findIV Method" );
        TestCBCOracle oracle = new TestCBCOracle();
        byte[] original = TEST_XML_STRING.getBytes();
        byte[] encryptedData = oracle.encryptTestData( original );
        byte[] iv = Arrays.copyOf( encryptedData, 16 );
        byte[] c1 = Arrays.copyOfRange( encryptedData, 16, 32 );

        System.out.println( "Default oracle" );
        FindIVMethodSimple fim = new FindIVMethodSimple( oracle, iv, c1, false );
        byte[] dec = fim.executeAttack();
        assertTrue( "The decrypted message was " + new String( dec ) + " and must be " + "equal to " + TEST_XML_STRING,
                    Arrays.equals( dec, original ) );

        oracle.setOracleType( FindIVMethodProperties.Type.IBM_DATAPOWER );
        fim = new FindIVMethodSimple( oracle, iv, c1, false );
        dec = fim.executeAttack();
        assertTrue( "The decrypted message was " + new String( dec ) + " and must be " + "equal to " + TEST_XML_STRING,
                    Arrays.equals( dec, original ) );
    }
}
