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

import java.util.Arrays;

import org.apache.log4j.Logger;

/**
 * @author Christian Altmeier
 */
public abstract class AbstractDoSAttack
    implements DoSAttack
{
    protected final Logger LOG = Logger.getLogger( this.getClass() );

    protected boolean initialized = false;

    protected boolean useNamespace = false;

    protected String namespace = "xmlns:";

    protected final int BEFORE = -1;

    protected final int EQUAL = 0;

    protected final int AFTER = 1;

    abstract int getCommentLength( PayloadPosition payloadPosition );

    @Override
    public abstract PayloadPosition[] getPossiblePossitions();

    @Override
    public String getUntamperedRequest( String xml, PayloadPosition payloadPosition )
    {
        verifyPayloadPosition( payloadPosition );

        int length = getCommentLength( payloadPosition );

        String startComment = "<!-- ";
        String endComment = " -->";

        length -= startComment.length();
        length -= endComment.length();

        StringBuilder builder = new StringBuilder( length );
        builder.append( startComment );
        for ( int i = 0; i < length; i++ )
        {
            builder.append( "c" );
        }
        builder.append( endComment );

        String utr;
        switch ( payloadPosition )
        {
            case ELEMENT:
                utr = payloadPosition.replacePlaceholder( xml, builder.toString() );
                break;
            case ATTRIBUTE:
                builder.append( payloadPosition.replacePlaceholder( xml, "" ) );
                utr = builder.toString();
                break;
            default:
                throw new IllegalArgumentException();
        }

        return utr;

    }

    protected void verifyPayloadPosition( PayloadPosition payloadPosition )
    {

        if ( payloadPosition == null || !Arrays.asList( getPossiblePossitions() ).contains( payloadPosition ) )
        {
            throw new IllegalArgumentException( "payloadPosition cannot be null, "
                + "and has to be an element of possiblePossitions!" );
        }
    }

    protected static int calculateMiddle( int valueA, int valueB )
    {
        int middle;
        int half = Math.abs( valueB - valueA ) / 2;

        if ( half > 0 )
        {
            int min = Math.min( valueA, valueB );
            middle = min + half;
        }
        else
        {
            middle = valueA;
        }

        return middle;
    }

    @Override
    public void setUseNamespace( boolean useNamespace )
    {
        this.useNamespace = useNamespace;
    }

    @Override
    public void initialize()
    {
        initialized = false;
    }

    @Override
    public DoSAttack clone()
        throws CloneNotSupportedException
    {
        return (DoSAttack) super.clone();
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

        DoSAttack that = (DoSAttack) obj;

        return this.getName().equals( that.getName() );
    }

}