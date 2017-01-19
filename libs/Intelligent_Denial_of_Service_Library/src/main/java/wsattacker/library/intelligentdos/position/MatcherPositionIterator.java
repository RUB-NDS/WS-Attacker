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

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;

/**
 * @author Christian Altmeier
 */
public class MatcherPositionIterator
    implements PositionIterator
{
    private final String xmlWithPlaceholder;

    private final Map<PayloadPosition, List<Finding>> findingsMap = Maps.newHashMap();

    private final Map<PayloadPosition, Iterator<Finding>> findingsIteratorMap = Maps.newHashMap();

    public MatcherPositionIterator( String xmlWithPlaceholder )
    {
        if ( StringUtils.isEmpty( xmlWithPlaceholder ) )
        {
            throw new IllegalArgumentException( "xmlWithPlaceholder cannot be null or empty!" );
        }

        this.xmlWithPlaceholder = xmlWithPlaceholder;

        initialize();
    }

    private void initialize()
    {
        for ( PayloadPosition payloadPosition : PayloadPosition.values() )
        {
            Matcher matcher =
                Pattern.compile( Pattern.quote( payloadPosition.placeholder() ) ).matcher( xmlWithPlaceholder );

            List<Finding> findings = Lists.newArrayList();
            int position = 1;
            while ( matcher.find() )
            {
                Finding finding = new Finding();
                finding.placeholder = matcher.group();
                finding.start = matcher.start();
                finding.end = matcher.end();
                finding.position = position;

                findings.add( finding );
                position++;
            }

            // update the count
            for ( Finding finding : findings )
            {
                finding.count = findings.size();
            }

            findingsMap.put( payloadPosition, findings );
            findingsIteratorMap.put( payloadPosition, findings.iterator() );
        }

    }

    @Override
    public boolean hasNext( PayloadPosition payloadPosition )
    {
        Iterator<Finding> iterator = findingsIteratorMap.get( payloadPosition );
        if ( iterator != null )
        {
            return iterator.hasNext();
        }
        else
        {
            return false;
        }
    }

    @Override
    public Position next( PayloadPosition payloadPosition )
    {
        Iterator<Finding> iterator = findingsIteratorMap.get( payloadPosition );
        if ( iterator != null )
        {
            return new MatcherPosition( xmlWithPlaceholder, iterator.next() );
        }
        else
        {
            throw new NoSuchElementException();
        }
    }

    @Override
    public void reset()
    {
        for ( Entry<PayloadPosition, List<Finding>> entry : findingsMap.entrySet() )
        {
            findingsIteratorMap.put( entry.getKey(), entry.getValue().iterator() );
        }
    }

    public static class Finding
    {
        String placeholder;

        int start, end, count, position;

        @Override
        public int hashCode()
        {
            int result = 31 + start;
            result = 31 * result + ( ( placeholder == null ) ? 0 : placeholder.hashCode() );
            long temp = Double.doubleToLongBits( end );
            result = 31 * result + (int) ( temp ^ ( temp >>> 32 ) );

            return result;
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

            Finding that = (Finding) obj;

            return this.start == that.start && this.end == that.end && this.placeholder.equals( that.placeholder );
        }
    }

}
