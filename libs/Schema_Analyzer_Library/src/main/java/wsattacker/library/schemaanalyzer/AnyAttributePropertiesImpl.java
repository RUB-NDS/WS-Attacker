/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
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
package wsattacker.library.schemaanalyzer;

import org.w3c.dom.Element;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * Wrapper Class. Can be expanded if additional features are necessary.
 */
public class AnyAttributePropertiesImpl
    implements AnyAttributeProperties
{

    Element anyElement, documentElement;

    public AnyAttributePropertiesImpl( Element anyElement, Element documentElement )
    {
        this.anyElement = anyElement;
        this.documentElement = documentElement;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.plugin.signatureWrapping.schema.AnyElementProperties# getDocumentElement()
     */
    @Override
    public Element getDocumentElement()
    {
        return documentElement;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.plugin.signatureWrapping.schema.AnyElementProperties# getProcessContentsAttribute()
     */
    @Override
    public String getProcessContentsAttribute()
    {
        String processContents = anyElement.getAttribute( "processContents" );
        if ( processContents == null || processContents.isEmpty() )
        {
            processContents = "strict";
        }
        return processContents;
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.plugin.signatureWrapping.schema.AnyElementProperties# getNamespaceAttributeValue()
     */
    @Override
    public String getNamespaceAttributeValue()
    {
        String namespace = anyElement.getAttribute( "namespace" );
        if ( namespace == null || namespace.isEmpty() )
        {
            namespace = "##any";
        }
        return namespace;
    }

    private boolean allowsDirectChildelements()
    {
        return getNamespaceAttributeValue().equals( "##any" );
    }

    @Override
    public int compareTo( AnyAttributeProperties other )
    {
        return DomUtilities.getFastXPath( documentElement ).compareTo( DomUtilities.getFastXPath( other.getDocumentElement() ) );
    }

    @Override
    public boolean equals( Object other )
    {
        boolean isEqual = false;
        if ( other instanceof AnyAttributePropertiesImpl )
        {
            isEqual =
                DomUtilities.getFastXPath( documentElement ).equals( DomUtilities.getFastXPath( ( (AnyElementProperties) other ).getDocumentElement() ) );
        }
        return isEqual;
    }

    @Override
    public int hashCode()
    {
        int hash = 5;
        hash =
            89 * hash
                + ( this.documentElement != null ? DomUtilities.getFastXPath( this.documentElement ).hashCode() : 0 );
        return hash;
    }

    @Override
    public String toString()
    {
        return String.format( "AnyElementProperties{processContents=%s, namespace=%s, documentElement=%s}",
                              getProcessContentsAttribute(), getNamespaceAttributeValue(),
                              DomUtilities.getFastXPath( documentElement ) );
    }
}
