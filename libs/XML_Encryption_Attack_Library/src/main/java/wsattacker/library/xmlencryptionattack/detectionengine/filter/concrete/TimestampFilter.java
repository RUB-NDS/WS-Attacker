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

package wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.xpath.XPathExpressionException;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter;
import static wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter.LOG;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.TimestampInfo;
import wsattacker.library.xmlencryptionattack.timestampelement.TimestampElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class TimestampFilter
    extends AbstractDetectionFilter
{
    public TimestampFilter( DetectFilterEnum filterType )
    {
        this.mFilterType = filterType;
        this.m_OutputFilter = new TimestampInfo( filterType );
    }

    @Override
    public AbstractDetectionInfo process()
    {
        try
        {
            detectTimestampElement();
        }
        catch ( XPathExpressionException ex )
        {
            LOG.warn( "Timestamp detection not executed : " + ex.getMessage() );
        }
        catch ( ParseException ex )
        {
            Logger.getLogger( TimestampFilter.class.getName() ).log( Level.SEVERE, null, ex );
        }

        return (TimestampInfo) this.m_OutputFilter;
    }

    private void detectTimestampElement()
        throws XPathExpressionException, ParseException
    {
        // detectionReport hinzufügen
        List<Element> timestampList;
        // TODO: SAML
        timestampList =
            (List<Element>) DomUtilities.evaluateXPath( m_InputFilter, "//*[local-name()='"
                + WSConstants.TIMESTAMP_TOKEN_LN + "' " + "and namespace-uri()='" + WSConstants.WSU_NS + "']" );
        if ( 1 == timestampList.size() )
        {
            TimestampElement timestamp = new TimestampElement( timestampList.get( 0 ) );
            ( (TimestampInfo) m_OutputFilter ).setTimestamp( timestamp );

            detectTimeDifference();
        }
        else if ( 1 < timestampList.size() )
        {
            LOG.warn( "multiple timestamps not supported yet" );
        }
    }

    private void detectTimeDifference()
        throws ParseException
    {
        final TimestampElement timestamp = ( (TimestampInfo) m_OutputFilter ).getTimestamp();
        Element createdEl = timestamp.getCreatedElement();
        Element expiresEl = timestamp.getExpiresElement();
        boolean inMilliseconds = createdEl.getTextContent().indexOf( '.' ) > 0;

        DateFormat dateFormat;
        if ( inMilliseconds )
        {
            timestamp.setIsMillisecondTime( true );
            dateFormat = new XmlSchemaDateFormat();
        }
        else
        {
            timestamp.setIsMillisecondTime( false );
            dateFormat = new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss'Z'" );
            dateFormat.setTimeZone( TimeZone.getTimeZone( "UTC" ) );
        }

        Calendar created = Calendar.getInstance();
        Calendar expires = Calendar.getInstance();

        created.setTime( dateFormat.parse( createdEl.getTextContent() ) );
        expires.setTime( dateFormat.parse( expiresEl.getTextContent() ) );

        int diff = (int) ( ( expires.getTimeInMillis() - created.getTimeInMillis() ) / 1000 );
        timestamp.setTimeDifference( diff );
    }
}
