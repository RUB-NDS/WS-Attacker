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
package wsattacker.library.signatureWrapping.util.signature;

import java.util.*;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class XPathElement
    implements ReferringElementInterface
{

    private static final String FILTER = "Filter";

    private final Element xpathElement;

    private final List<Payload> payloads;

    private final List<Element> matchedElements;

    private String workingXPath;

    public XPathElement( Element xpath )
    {
        this.xpathElement = xpath;
        this.workingXPath = "";
        payloads = new ArrayList<Payload>();
        log().trace( String.format( "Searching matched Elements for %s", DomUtilities.getFastXPath( xpath ) ) );
        // Get the matched Elements by this XPath
        matchedElements = new ArrayList<Element>();
        try
        {
            matchedElements.addAll( (List<Element>) DomUtilities.evaluateXPath( xpath.getOwnerDocument(),
                                                                                getExpression() ) );
        }
        catch ( XPathExpressionException e )
        {
            throw new IllegalStateException( String.format( "Could not evaluate XPath >> %s <<", getExpression() ), e );
        }

        log().trace( String.format( "Found: %s", matchedElements ) );
        // Add an Payload for each match
        int anz = matchedElements.size();
        for ( int i = 0; i < anz; ++i )
        {
            Element signedElement = matchedElements.get( i );
            Payload o = new Payload( this, signedElement );
            payloads.add( o );
        }
    }

    @Override
    public String getXPath()
    {
        if ( workingXPath.isEmpty() )
        {
            workingXPath = xpathElement.getTextContent();
        }
        return workingXPath;
    }

    @Override
    public void setXPath( String workingXPath )
    {
        this.workingXPath = workingXPath;
    }

    public Element getXPathElement()
    {
        return xpathElement;
    }

    @Override
    public Element getElementNode()
    {
        return xpathElement;
    }

    public List<Payload> getPayloads()
    {
        return payloads;
    }

    public String getExpression()
    {
        return xpathElement.getTextContent();
    }

    public String getFilter()
    {
        return xpathElement.getAttribute( FILTER );
    }

    public List<Element> getReferencedElements()
    {
        return matchedElements;
    }

    @Override
    public boolean equals( Object o )
    {
        boolean result = false;
        if ( o instanceof XPathElement )
        {
            XPathElement xpe = (XPathElement) o;
            result = xpe.getFilter().equals( getFilter() ) && xpe.getExpression().equals( getExpression() );
        }
        return result;
    }

    @Override
    public int hashCode()
    {
        int hash = 5;
        hash = 53 * hash + ( getFilter() != null ? getFilter().hashCode() : 0 );
        hash = 53 * hash + ( getExpression() != null ? getExpression().hashCode() : 0 );
        return hash;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append( "XPathElement{xpathElement=" ).append( DomUtilities.getFastXPath( xpathElement ) );
        sb.append( ", matchedElements=" ).append( matchedElements );
        sb.append( ", workingXPath=" ).append( workingXPath );
        sb.append( '}' ).toString();
        return sb.toString();
    }

    private Logger log()
    {
        return Logger.getLogger( getClass() );
    }
}
