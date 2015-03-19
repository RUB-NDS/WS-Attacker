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
package wsattacker.plugin.dos.dosExtension.util;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;

import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionInterface;

/**
 * @author Christian Altmeier
 */
public class UtilHashDoS
{

    private static final String DEFAULT_ATTRIBUTENAME = "abcdefghijabcdefghijabcdefghij";

    public static String generateUntampered( CollisionInterface collisionInterface, int numberOfAttributes,
                                             boolean useNamespace )
    {

        String attributeName =
            UtilHashDoS.determineUntamperedAttributeName( collisionInterface, numberOfAttributes, useNamespace );

        int size = String.valueOf( numberOfAttributes ).length();

        String prefix = "";
        if ( useNamespace == true )
        {
            prefix = "xmlns:";
        }

        // create final SOAP message with payload
        StringBuilder sb = new StringBuilder( "" );
        for ( int i = 0; i < numberOfAttributes; i++ )
        {
            sb.append( " " ).append( prefix ).append( attributeName );
            sb.append( StringUtils.leftPad( String.valueOf( i ), size, '0' ) );
            sb.append( "=\"" ).append( i ).append( "\"" );
        }

        return sb.toString();
    }

    public static String determineUntamperedAttributeName( CollisionInterface collisionInterface,
                                                           int numberOfAttributes, boolean useNamespace )
    {
        String attributeName = DEFAULT_ATTRIBUTENAME;

        StringBuilder builder = new StringBuilder( "" );

        // n viele Kollisionen erzeugen
        collisionInterface.genNCollisions( numberOfAttributes, builder, useNamespace );
        int indexOf = builder.indexOf( "=" );
        if ( indexOf != -1 )
        {
            int start = 0;
            if ( builder.indexOf( ":" ) != -1 )
            {
                start = builder.indexOf( ":" ) + 1;
            }

            CharSequence subSequence = builder.subSequence( start, indexOf );
            // length for the attribute name -> e.g. aaaa = 4
            int count = subSequence.length();
            // substract the count -> e.g. 10 elements -> aaa0 - aaa9
            count -= String.valueOf( numberOfAttributes ).length();

            if ( count > 0 )
            {
                attributeName = RandomStringUtils.randomAlphabetic( count );
            }
        }

        return attributeName;
    }

}
