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
package wsattacker.library.intelligentdos.position;

import java.util.regex.Pattern;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.position.MatcherPositionIterator.Finding;

/**
 * @author Christian Altmeier
 */
public class MatcherPosition
    implements Position
{

    private final String xmlWithPlaceholder;

    private final Finding finding;

    public MatcherPosition( String xmlWithPlaceholder, Finding finding )
    {
        this.xmlWithPlaceholder = xmlWithPlaceholder;
        this.finding = finding;
    }

    /*
     * (non-Javadoc)
     * @see
     * wsattacker.library.intelligentdos.position.Position#createContent(wsattacker.library.intelligentdos.dos.DoSAttack
     * .PayloadPosition)
     */
    @Override
    public String createPlaceholder( PayloadPosition payloadPosition )
    {
        String pre = removePlaceholder( xmlWithPlaceholder.substring( 0, finding.start ) );
        String post = removePlaceholder( xmlWithPlaceholder.substring( finding.end, xmlWithPlaceholder.length() ) );

        return pre + finding.placeholder + post;
    }

    private String removePlaceholder( String s )
    {
        String replaceAll = s.replaceAll( Pattern.quote( PayloadPosition.ELEMENT.placeholder() ), "" );
        return replaceAll.replaceAll( Pattern.quote( PayloadPosition.ATTRIBUTE.placeholder() ), "" );
    }

    @Override
    public int hashCode()
    {
        return finding.hashCode();
    }

    @Override
    public boolean equals( Object obj )
    {
        if ( obj == null )
        {
            return false;
        }

        if ( obj == this )
        {
            return true;
        }

        if ( !obj.getClass().equals( getClass() ) )
        {
            return false;
        }

        MatcherPosition that = (MatcherPosition) obj;

        return this.finding.equals( that.finding );
    }

    @Override
    public String toString()
    {
        return String.format( "position %d / %d", new Object[] { finding.position, finding.count } );
    }

}
