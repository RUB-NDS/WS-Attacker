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
package wsattacker.library.signatureWrapping.util.timestamp;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.*;
import javax.xml.xpath.XPathExpressionException;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * Helper class to manipulate (update) time conditions in SAML elements. The difference between notBefore and
 * notOnOrAfter are kept.
 * 
 * @author christian
 */
public final class SamlConditionsUpdater
{

    final public static DateFormat inMilli = new XmlSchemaDateFormat();

    final public static DateFormat normal = new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss'Z'" );

    public static DateFormat df = inMilli;

    public final static String XPATH_NOT_BEFORE = "//attribute::*[local-name()='NotBefore']";

    public final static String XPATH_NOT_ON_OR_AFTER = "//attribute::*[local-name()='NotOnOrAfter']";

    private SamlConditionsUpdater()
    {
    }

    public static void updateConditionsElement( Element conditionsElement, int beforeSec, int afterSec )
    {
        Calendar notBefore = Calendar.getInstance();
        Calendar notOnOrAfter = (Calendar) notBefore.clone();
        notBefore.add( Calendar.SECOND, -1 * beforeSec );
        notOnOrAfter.add( Calendar.SECOND, afterSec );

        conditionsElement.setAttribute( "NotBefore", df.format( notBefore.getTime() ) );
        conditionsElement.setAttribute( "NotOnOrAfter", df.format( notOnOrAfter.getTime() ) );
    }

    public static void updateTimestamps( Document document, int beforeSeconds, int afterSeconds )
    {
        Calendar notBefore = Calendar.getInstance();
        notBefore.add( Calendar.SECOND, -1 * beforeSeconds );
        Calendar notOnOrAfter = Calendar.getInstance();
        notOnOrAfter.setTime( notBefore.getTime() );
        notOnOrAfter.add( Calendar.SECOND, afterSeconds );
        updateTimestamps( document, notBefore, notOnOrAfter );

    }

    public static void updateTimestamps( Document document, Calendar notBefore, Calendar notOnOrAfter )
    {
        try
        {
            XmlSchemaDateFormat df = new XmlSchemaDateFormat();

            List<? extends Node> notBeforeList = DomUtilities.evaluateXPath( document, XPATH_NOT_BEFORE );
            for ( Node n : notBeforeList )
            {
                Attr notBeforeAttr = (Attr) n;
                notBeforeAttr.setTextContent( df.format( notBefore.getTime() ) );
            }
            List<? extends Node> notOnOrAfterList = DomUtilities.evaluateXPath( document, XPATH_NOT_ON_OR_AFTER );
            for ( Node n : notOnOrAfterList )
            {
                Attr notOnOrAfterAttr = (Attr) n;
                notOnOrAfterAttr.setTextContent( df.format( notOnOrAfter.getTime() ) );
            }
        }
        catch ( XPathExpressionException ex )
        {
            Logger.getLogger( SamlConditionsUpdater.class.getName() ).log( Level.SEVERE, null, ex );
        }
    }

    public static void updateTimestampsByXPath( Document document, String xpathToFindTimestampAttr, Calendar calendar )
        throws XPathExpressionException
    {
        List<? extends Node> attrList = DomUtilities.evaluateXPath( document, XPATH_NOT_BEFORE );
        for ( Node n : attrList )
        {
            Attr notBefore = (Attr) n;
            notBefore.setTextContent( df.format( calendar.getTime() ) );
        }
    }
}
