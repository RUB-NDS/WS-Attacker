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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.schemaanalyzer.AnyElementProperties;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Christian Altmeier
 */
public class AnyElementPosition
    implements Position
{

    private final String xmlMessage;

    private final AnyElementProperties anyElement;

    public AnyElementPosition( String xmlMessage, AnyElementProperties anyElement )
    {
        this.xmlMessage = xmlMessage;
        this.anyElement = anyElement;
    }

    @Override
    public String createPlaceholder( PayloadPosition payloadPosition )
    {
        String domToString = "";
        try
        {
            Document stringToDom = DomUtilities.stringToDom( xmlMessage );
            Element correspondingElement =
                DomUtilities.findCorrespondingElement( stringToDom, anyElement.getDocumentElement() );

            domToString = payloadPosition.createAndReplacePlaceholder( stringToDom, correspondingElement );
        }
        catch ( SAXException e )
        {
            // shouldn't happen, because we already parsed the xmlMessage
        }

        return domToString;
    }

    @Override
    public int hashCode()
    {
        return anyElement.hashCode();
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

        AnyElementPosition that = (AnyElementPosition) obj;

        return this.anyElement.equals( that.anyElement );
    }

    @Override
    public String toString()
    {
        String localName;
        if ( anyElement != null && anyElement.getDocumentElement() != null )
        {
            localName = anyElement.getDocumentElement().getLocalName();
        }
        else
        {
            localName = "";
        }

        return localName;
    }

}
