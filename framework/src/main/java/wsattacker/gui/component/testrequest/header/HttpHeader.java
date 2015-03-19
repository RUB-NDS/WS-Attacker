/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.gui.component.testrequest.header;

import com.eviware.soapui.support.types.StringToStringsMap;
import java.util.List;
import java.util.Map;

/**
 * @author dev
 */
public final class HttpHeader
{

    private static final String HEADER_SPLIT_PATTERN = ": ";

    private static final String SOAPUI_STATUSLINE_IDENTIFIER = "#status#";

    private static final String NEWLINE = "\n";

    public static String stringToStringsMapToString( final StringToStringsMap headers )
    {
        StringBuilder result = new StringBuilder();
        if ( headers.containsKey( SOAPUI_STATUSLINE_IDENTIFIER ) )
        {
            final List<String> statusline = headers.get( SOAPUI_STATUSLINE_IDENTIFIER );
            result.append( statusline );
            result.append( NEWLINE ).append( NEWLINE );
        }
        for ( Map.Entry<String, List<String>> entrySet : headers.entrySet() )
        {
            String key = entrySet.getKey();
            if ( SOAPUI_STATUSLINE_IDENTIFIER.equals( key ) )
            {
                continue;
            }
            List<String> values = entrySet.getValue();
            for ( String value : values )
            {
                result.append( key ).append( HEADER_SPLIT_PATTERN ).append( value );
                result.append( NEWLINE );
            }
        }
        return result.toString().trim();
    }

    public static StringToStringsMap stringToStringsToStringMap( String headerText )
    {
        final StringToStringsMap result = new StringToStringsMap();
        for ( String row : headerText.split( NEWLINE ) )
        {
            String[] entry = row.split( HEADER_SPLIT_PATTERN, 2 );
            result.add( entry[0], entry[1] );
        }
        return result;
    }

}
