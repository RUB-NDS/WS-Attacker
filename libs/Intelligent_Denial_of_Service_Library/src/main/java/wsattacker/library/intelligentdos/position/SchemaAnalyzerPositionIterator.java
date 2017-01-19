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

import com.google.common.collect.Maps;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.schemaanalyzer.AnyElementProperties;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Christian Altmeier
 */
public class SchemaAnalyzerPositionIterator
    implements PositionIterator
{

    private final static Logger LOG = Logger.getLogger( SchemaAnalyzerPositionIterator.class );

    private final SchemaAnalyzer schemaAnalyzer;

    // set of all expansion points
    private Set<AnyElementProperties> expansionPoints;

    private final Map<PayloadPosition, Iterator<AnyElementProperties>> anyElementIteratorMap = Maps.newHashMap();

    private final String xmlMessage;

    public SchemaAnalyzerPositionIterator( SchemaAnalyzer schemaAnalyzer, String xmlMessage )
    {
        if ( schemaAnalyzer == null )
        {
            throw new IllegalArgumentException( "schemaAnalyzer cannot be null!" );
        }

        this.schemaAnalyzer = schemaAnalyzer;
        this.xmlMessage = xmlMessage;

        initialize();
    }

    private void initialize()
    {
        try
        {
            Document toAnalyze = DomUtilities.stringToDom( xmlMessage );
            expansionPoints = findExpansionPoints( toAnalyze );
            reset();

            LOG.info( "Found " + expansionPoints.size() + " expansion points" );
        }
        catch ( SAXException e )
        {
            throw new IllegalArgumentException( "xmlMessage cannot be parsed", e );
        }
    }

    private Set<AnyElementProperties> findExpansionPoints( Document toAnalyze )
    {
        Element documentElement = toAnalyze.getDocumentElement();

        return schemaAnalyzer.findExpansionPoint( documentElement );
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.position.PositionIterator#reset()
     */
    @Override
    public void reset()
    {
        for ( PayloadPosition payloadPosition : new PayloadPosition[] { PayloadPosition.ELEMENT,
            PayloadPosition.ATTRIBUTE } )
        {
            anyElementIteratorMap.put( payloadPosition, expansionPoints.iterator() );
        }
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.position.PositionIterator#hasNext(
     * wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition)
     */
    @Override
    public boolean hasNext( PayloadPosition payloadPosition )
    {
        Iterator<AnyElementProperties> iterator = anyElementIteratorMap.get( payloadPosition );
        if ( iterator != null )
        {
            return iterator.hasNext();
        }
        else
        {
            return false;
        }
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.position.PositionIterator#next(wsattacker
     * .library.intelligentdos.dos.DoSAttack.PayloadPosition)
     */
    @Override
    public Position next( PayloadPosition payloadPosition )
    {
        Iterator<AnyElementProperties> iterator = anyElementIteratorMap.get( payloadPosition );
        if ( iterator != null )
        {
            return new AnyElementPosition( xmlMessage, iterator.next() );
        }
        else
        {
            throw new NoSuchElementException();
        }
    }

}
