/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.util;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import wsattacker.plugin.dos.CoerciveParsing;
import wsattacker.util.SoapUtilities;

/**
 * @author ianyo
 */
public class UtilDos
{

    /**
     * Gets the first child of the SOAP Body OR SOAP Envelop from Document.
     * 
     * @param doc
     * @return
     */
    public static Node getSoapBody( Document doc )
    {
        XPath xpath = XPathFactory.newInstance().newXPath();
        Node soapBody = null;
        try
        {
            soapBody = (Node) xpath.evaluate( "/Envelope/Body", doc, XPathConstants.NODE );
            if ( soapBody == null )
            {
                soapBody = (Node) xpath.evaluate( "/Envelope/*[2]", doc, XPathConstants.NODE );
                if ( soapBody == null )
                {
                    throw new NullPointerException();
                }
            }
        }
        catch ( XPathExpressionException ex )
        {
            Logger.getLogger( CoerciveParsing.class.getName() ).log( Level.SEVERE,
                                                                     "Xpath is broken - please check syntax in source",
                                                                     ex );
        }
        catch ( NullPointerException ex )
        {
            Logger.getLogger( CoerciveParsing.class.getName() ).log( Level.SEVERE,
                                                                     "Invalid SoapRequest - Xpath finds nothing for /Envelope/Body or /Envelope/*[1]",
                                                                     ex );
        }

        return soapBody;
    }

    public static Node getSoapEnvelope( Document doc )
    {
        XPath xpath = XPathFactory.newInstance().newXPath();
        Node soapBody = null;
        try
        {
            soapBody = (Node) xpath.evaluate( "/Envelope", doc, XPathConstants.NODE );
            if ( soapBody == null )
            {
                soapBody = (Node) xpath.evaluate( "/*[1]", doc, XPathConstants.NODE );
                if ( soapBody == null )
                {
                    throw new NullPointerException();
                }
            }
        }
        catch ( XPathExpressionException ex )
        {
            Logger.getLogger( CoerciveParsing.class.getName() ).log( Level.SEVERE,
                                                                     "Xpath is broken - please check syntax in source",
                                                                     ex );
        }
        catch ( NullPointerException ex )
        {
            Logger.getLogger( CoerciveParsing.class.getName() ).log( Level.SEVERE,
                                                                     "Invalid SoapRequest - Xpath finds nothing for /Envelope or /[1]",
                                                                     ex );
        }

        return soapBody;
    }

    public static Node getSoapHeader( Document doc )
    {
        XPath xpath = XPathFactory.newInstance().newXPath();
        Node soapBody = null;
        try
        {
            soapBody = (Node) xpath.evaluate( "/Envelope/Header", doc, XPathConstants.NODE );
            if ( soapBody == null )
            {
                soapBody = (Node) xpath.evaluate( "/Envelope/*[1]", doc, XPathConstants.NODE );
                if ( soapBody == null )
                {
                    throw new NullPointerException();
                }
            }
        }
        catch ( XPathExpressionException ex )
        {
            Logger.getLogger( CoerciveParsing.class.getName() ).log( Level.SEVERE,
                                                                     "Xpath is broken - please check syntax in source",
                                                                     ex );
        }
        catch ( NullPointerException ex )
        {
            Logger.getLogger( CoerciveParsing.class.getName() ).log( Level.SEVERE,
                                                                     "Invalid SoapRequest - Xpath finds nothing for /Envelope/Header or /Envelope/*[1]",
                                                                     ex );
        }

        return soapBody;
    }

    /**
     * Gets the first child of the SOAP Body from an XML String. This does exactly the same as getBodyChildWithXPath but
     * it demonstrates the power of WS-Attackers SoapUtilities.
     * 
     * @param xmlContent
     * @return
     * @throws SOAPException
     */
    public static Node getBodyChild( String xmlContent )
        throws SOAPException
    {
        SOAPMessage sm = SoapUtilities.stringToSoap( xmlContent );
        // we need to return the first soapChild because there could also
        // be a TextNode (whitespaces) as sm.getSOAPBody().getFirstChild()
        List<SOAPElement> bodyChilds = SoapUtilities.getSoapChilds( sm.getSOAPBody() );
        if ( bodyChilds.size() > 0 )
        {
            return bodyChilds.get( 0 );
        }
        else
        {
            return null;
        }
    }

}
