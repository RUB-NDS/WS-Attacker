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
package wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc;

import java.util.Random;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;

/**
 * Vector generator for CBC ciphertexts
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public final class CBCVectorGenerator
{

    /**
     * No instantiation needed, only one static method used
     */
    private CBCVectorGenerator()
    {

    }

    /**
     * always 256 independently of the algorithm
     */
    private static final int VECTOR_SIZE = 256;

    /**
     * In order to test if the given server is vulnerable to the attack, it is possible to generate 256 32-byte long
     * vectors. Each vector has a different value on the 16-th position (last byte in the initialization vector). These
     * vectors result in 256*4 different plaintexts, each having a different value in its last padding byte (see CBC for
     * more information). In addition, for each different padding byte there are four different first bytes. This should
     * ensure that at least one plaintext is correctly unpadded and contains correct byte at the first position. If the
     * server is vulnerable to the attack, it should respond with a different response at least to one of the messages.
     * 
     * @param cipherBlockSize
     * @return
     */
    public static OracleRequest[] generateVectors( int cipherBlockSize )
    {
        Random r = new Random();
        byte[] b = new byte[cipherBlockSize * 2];
        r.nextBytes( b );
        OracleRequest[] oracleRequests = new OracleRequest[VECTOR_SIZE * 4];
        for ( int i = 0; i < VECTOR_SIZE; i++ )
        {
            byte[] vector = b.clone();
            vector[cipherBlockSize - 1] = (byte) i;
            oracleRequests[i * 4] = new OracleRequest();
            oracleRequests[i * 4].setEncryptedData( vector );

            byte[] vector2 = vector.clone();
            vector2[0] = (byte) ( vector2[0] ^ 0x40 );
            oracleRequests[i * 4 + 1] = new OracleRequest();
            oracleRequests[i * 4 + 1].setEncryptedData( vector2 );

            byte[] vector3 = vector.clone();
            vector3[0] = (byte) ( vector3[0] ^ 0x80 );
            oracleRequests[i * 4 + 2] = new OracleRequest();
            oracleRequests[i * 4 + 2].setEncryptedData( vector3 );

            byte[] vector4 = vector.clone();
            vector4[0] = (byte) ( vector4[0] ^ 0xB0 );
            oracleRequests[i * 4 + 3] = new OracleRequest();
            oracleRequests[i * 4 + 3].setEncryptedData( vector4 );

        }
        return oracleRequests;
    }
}
