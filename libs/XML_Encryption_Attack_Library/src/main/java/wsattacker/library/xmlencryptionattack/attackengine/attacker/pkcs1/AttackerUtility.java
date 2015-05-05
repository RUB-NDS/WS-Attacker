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
package wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1;

import java.math.BigInteger;
import java.util.List;

/**
 * Utility routines for attacks.
 * 
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1 Aug 1, 2013
 */
public final class AttackerUtility
{

    /**
     * Private constructor - Utility class only.
     */
    private AttackerUtility()
    {
    }

    /**
     * Computes the Greatest Common Divisor of two integers.
     * 
     * @param a First Integer
     * @param b Second Integer
     * @return Greatest Common Divisor of both integers
     */
    public static int findGCD( final int a, final int b )
    {
        if ( b == 0 )
        {
            return a;
        }
        return findGCD( b, a % b );
    }

    /**
     * Computes the Greatest Common Divisor of two BigIntegers.
     * 
     * @param a First BigInteger
     * @param b Second BigInteger
     * @return Greatest Common Divisor of both BigIntegers
     */
    public static BigInteger findGCD( final BigInteger a, final BigInteger b )
    {
        if ( b.compareTo( BigInteger.ZERO ) == 0 )
        {
            return a;
        }
        return findGCD( b, a.mod( b ) );
    }

    /**
     * Computes the Least Common Multiple of two integers.
     * 
     * @param a First Integer
     * @param b Second Integer
     * @return Least Common Multiple of both integers
     */
    public static int findLCM( final int a, final int b )
    {
        int result = 0;
        int num1, num2;
        if ( a > b )
        {
            num1 = a;
            num2 = b;
        }
        else
        {
            num1 = b;
            num2 = a;
        }
        for ( int i = 1; i <= num2; i++ )
        {
            if ( ( num1 * i ) % num2 == 0 )
            {
                result = i * num1;
            }
        }

        return result;
    }

    /**
     * Computes the Least Common Multiple of two BigIntegers.
     * 
     * @param ba First BigInteger
     * @param bb Second BigInteger
     * @return Least Common Multiple of both BigIntegers
     */
    public static BigInteger findLCM( final BigInteger ba, final BigInteger bb )
    {
        BigInteger result = BigInteger.ZERO;
        long a = ba.longValue();
        long b = bb.longValue();
        long num1, num2;
        if ( a > b )
        {
            num1 = a;
            num2 = b;
        }
        else
        {
            num1 = b;
            num2 = a;
        }
        for ( int i = 1; i <= num2; i++ )
        {
            if ( ( num1 * i ) % num2 == 0 )
            {
                result = BigInteger.valueOf( i * num1 );
            }
        }

        return result;
    }

    /**
     * Computes the Least Common Multiple of a list of BigIntegers.
     * 
     * @param numbers List of BigIntegers
     * @return Least Common Multiple of all BigIntegers contained in the list
     */
    public static BigInteger findLCM( final List<BigInteger> numbers )
    {
        BigInteger result = numbers.get( 0 );
        for ( int i = 1; i < numbers.size(); i++ )
        {
            result = findLCM( result, numbers.get( i ) );
        }
        return result;
    }

    /**
     * Corrects the length of a byte array to a multiple of a passed blockSize.
     * 
     * @param array Array which size should be corrected
     * @param blockSize Blocksize - the resulting array length will be a multiple of it
     * @param removeSignByte If set to TRUE leading sign bytes will be removed
     * @return Size corrected array (maybe padded or stripped the sign byte)
     */
    public static byte[] correctSize( final byte[] array, final int blockSize, final boolean removeSignByte )
    {
        int remainder = array.length % blockSize;
        byte[] result = array;
        byte[] tmp;

        if ( removeSignByte && remainder > 0 && result[0] == 0x0 )
        {
            // extract signing byte if present
            tmp = new byte[result.length - 1];
            System.arraycopy( result, 1, tmp, 0, tmp.length );
            result = tmp;
            remainder = tmp.length % blockSize;
        }

        if ( remainder > 0 )
        {
            // add zeros to fit size
            tmp = new byte[result.length + blockSize - remainder];
            System.arraycopy( result, 0, tmp, blockSize - remainder, result.length );
            result = tmp;
        }

        return result;
    }
}
