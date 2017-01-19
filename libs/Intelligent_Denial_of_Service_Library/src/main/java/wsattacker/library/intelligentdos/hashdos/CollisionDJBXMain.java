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

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.Set;

/**
 * @author Christian Altmeier
 */
public class CollisionDJBXMain
{

    public static void main( String[] args )
    {
        if ( args.length != 2 )
        {
            System.exit( -1 );
        }

        int numberCollisions = 0;
        try
        {
            numberCollisions = Integer.parseInt( args[0] );

        }
        catch ( NumberFormatException e )
        {
            System.exit( -1 );
        }

        CollisionDJBX collisionDJBX = new CollisionDJBX();
        Set<String> generateCollionsMeetInTheMiddle = collisionDJBX.generateCollionsMeetInTheMiddle( numberCollisions );

        BufferedWriter writer = null;
        try
        {
            writer =
                new BufferedWriter( new OutputStreamWriter( new FileOutputStream( args[1] ), Charset.defaultCharset() ) );

            for ( String string : generateCollionsMeetInTheMiddle )
            {
                writer.write( string + "\n" );
            }
        }
        catch ( IOException e )
        {
        }
        finally
        {
            if ( writer != null )
            {
                try
                {
                    writer.close();
                }
                catch ( IOException e )
                {
                    // nothing
                }
            }
        }
    }
}
