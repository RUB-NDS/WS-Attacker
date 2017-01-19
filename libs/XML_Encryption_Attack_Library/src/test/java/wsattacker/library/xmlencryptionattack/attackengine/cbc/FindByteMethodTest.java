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
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.FindByteMethod;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class FindByteMethodTest
{

    /**
     * Test of executeAttack method, of class FindByteMethod.
     */
    @Test
    public void testExecuteAttack()
        throws Exception
    {
        TestCBCOracle oracle = new TestCBCOracle();
        byte[] encryptedData = oracle.encryptTestData( "abc".getBytes() );
        byte[] iv = Arrays.copyOf( encryptedData, 16 );
        byte[] c1 = Arrays.copyOfRange( encryptedData, 16, 32 );
        FindByteMethod fbMethod = new FindByteMethod( oracle, iv, c1 );

        assertTrue( "the first byte is a (97)", fbMethod.executeAttack( 0 ) == 97 );
        assertTrue( "the second byte is b (98)", fbMethod.executeAttack( 1 ) == 98 );
        assertTrue( "the third byte is c (99)", fbMethod.executeAttack( 2 ) == 99 );
    }
}
