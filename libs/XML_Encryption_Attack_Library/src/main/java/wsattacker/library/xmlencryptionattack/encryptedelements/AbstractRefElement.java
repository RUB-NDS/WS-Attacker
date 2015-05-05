/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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

package wsattacker.library.xmlencryptionattack.encryptedelements;

import java.util.ArrayList;
import java.util.List;
import javax.xml.xpath.XPathExpressionException;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import static wsattacker.library.signatureWrapping.util.signature.ReferenceElement.LOG;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis Kupser
 */
public abstract class AbstractRefElement
{

    /**
     *
     */
    protected Element m_Reference;

    /**
     *
     */
    protected Element m_ReferredElement;

    /**
     *
     */
    protected String m_URI;

    /**
     * @return
     */
    public Element getReference()
    {
        return m_Reference;
    }

    /**
     * @return
     */
    public Element getReferredElement()
    {
        return m_ReferredElement;
    }

    /**
     * @param uri
     * @param reference
     * @param refIdx
     * @return
     */
    protected Element getReferredElementFromURI( String uri, Element reference, int refIdx )
    {
        Element referredElement = null;

        String ref = uri;
        if ( ref.charAt( 0 ) == '#' )
        {
            ref = ref.substring( 1 );
        } // remove #
        List<? extends Node> referenced;
        // First Try: Search for @Id Attribute
        try
        {
            referenced =
                (List<Element>) DomUtilities.evaluateXPath( reference.getOwnerDocument(),
                                                            String.format( "//*[@Id='%s']", ref ) );
        }
        catch ( XPathExpressionException e )
        {
            referenced = new ArrayList<Element>();
        }
        // Second Try: Search for @wsu:Id Attribute
        if ( referenced.isEmpty() )
        {
            referenced = DomUtilities.findElementByWsuId( reference.getOwnerDocument(), ref );
        }
        // Third Try: Search for any Attribute with specified value
        if ( referenced.isEmpty() )
        {
            referenced = DomUtilities.findAttributeByValue( reference.getOwnerDocument(), ref );
        }

        if ( referenced.size() == 1 )
        {
            Node n = referenced.get( 0 );
            if ( n.getNodeType() == Node.ELEMENT_NODE )
            {
                referredElement = (Element) referenced.get( 0 );
            }
            else if ( n.getNodeType() == Node.ATTRIBUTE_NODE )
            {
                referredElement = ( (Attr) referenced.get( 0 ) ).getOwnerElement();
            }
            else
            {
                throw new NullPointerException( "Don't know how to handle match:" + n.toString() + "("
                    + n.getClass().getName() + ")" );
            }
        }
        else if ( referenced.size() > 1 )
        {
            try
            {
                List<Attr> attrList = (List<Attr>) referenced;

                LOG.warn( "There are " + referenced.size() + " possible References which machtes the URI '" + ref
                    + "' (" + DomUtilities.nodelistToFastXPathList( referenced )
                    + "). This is invalid and must produce errors." );

                // looking for exact matche AssertionID and prefer it
                for ( Attr attribute : attrList )
                {
                    if ( attribute.getLocalName().toLowerCase().equals( "assertionid" ) )
                    {
                        referredElement = attribute.getOwnerElement();
                    }
                }
                // looking for exact matche ID and prefer it
                if ( referredElement == null )
                {
                    for ( Attr attribute : attrList )
                    {
                        if ( attribute.getLocalName().toLowerCase().equals( "id" ) )
                        {
                            referredElement = attribute.getOwnerElement();
                        }
                    }
                }
                // looking for substring matching id
                if ( referredElement == null )
                {
                    for ( Attr attribute : attrList )
                    {
                        if ( attribute.getLocalName().toLowerCase().contains( "id" ) )
                        {
                            referredElement = attribute.getOwnerElement();
                        }
                    }
                }
            }
            catch ( ClassCastException e )
            {
                // case two encData with same Id => get the right one from index
                referredElement = (Element) referenced.get( refIdx );
                // throw new IllegalStateException( "This should never happen", e );
            }

        }
        else if ( referenced.isEmpty() )
        {
            LOG.warn( String.format( "Could not find any References which machtes the URI >> %s <<. "
                + "No Encryption-Reference Element found.", ref ) );
            throw new NullPointerException( "Could not de-reference encrypted element" );
        }

        return referredElement;
    }

    /**
     * @return
     */
    public String getURI()
    {
        return m_URI;
    }

    void setURI( String uri )
    {
        m_URI = uri;
    }

}
