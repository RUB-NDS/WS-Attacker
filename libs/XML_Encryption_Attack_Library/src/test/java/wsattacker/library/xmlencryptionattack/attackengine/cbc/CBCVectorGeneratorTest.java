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

import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.CBCVectorGenerator;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class CBCVectorGeneratorTest
{

    Logger LOG = Logger.getLogger( CBCVectorGenerator.class );

    public CBCVectorGeneratorTest()
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
     * Test of generateVectors method, of claCBCVectorGeneratortor.
     */
    @Test
    public void testGenerateVectors()
    {
        LOG.info( "generateVectors test" );
        int cipherBlockSize = CryptoConstants.AES_BLOCK_SIZE;
        OracleRequest[] result = CBCVectorGenerator.generateVectors( cipherBlockSize );
        assertTrue( "Vector generator should return 256 * 4 vectors", result.length == 256 * 4 );
        for ( int i = 0; i < 256; i++ )
        {
            assertTrue( "Each vector should have a different value in its 15th " + "byte.",
                        result[i * 4].getEncryptedData()[15] == (byte) i );
        }

    }
}
