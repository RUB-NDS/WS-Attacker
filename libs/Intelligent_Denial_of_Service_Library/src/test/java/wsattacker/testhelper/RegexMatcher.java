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
package wsattacker.testhelper;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

/**
 * @author Christian Altmeier
 */
public class RegexMatcher
    extends BaseMatcher<String>
{
    private final String regex;

    public RegexMatcher( String regex )
    {
        this.regex = regex;
    }

    @Override
    public boolean matches( Object o )
    {
        return ( (String) o ).matches( regex );

    }

    @Override
    public void describeTo( Description description )
    {
        description.appendText( "matches regex=" + regex );
    }

    public static RegexMatcher matches( String regex )
    {
        return new RegexMatcher( regex );
    }
}
