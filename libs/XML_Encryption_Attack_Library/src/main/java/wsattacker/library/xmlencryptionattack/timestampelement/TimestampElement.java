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

package wsattacker.library.xmlencryptionattack.timestampelement;

import java.text.ParseException;
import org.apache.ws.security.WSConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.timestamp.TimestampUpdateHelper;
import static wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter.LOG;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 */
public final class TimestampElement
    extends TimestampBase
{
    private Element m_CreatedPayload = null;

    private Element m_ExpiresPayload = null;

    private Element m_CreatedElement = null;

    private Element m_ExpiresElement = null;

    public TimestampElement( Element timestamp )
    {
        initTimestamp( timestamp );
    }

    private void initTimestamp( Element timestamp )
        throws IllegalArgumentException
    {
        this.m_TimestampElement = timestamp;
        for ( Node cur = m_TimestampElement.getFirstChild(); cur != null; cur = cur.getNextSibling() )
        {
            if ( cur.getNodeType() == Node.ELEMENT_NODE )
            {
                if ( WSConstants.CREATED_LN.equals( cur.getLocalName() )
                    && WSConstants.WSU_NS.equals( cur.getNamespaceURI() ) )
                {
                    this.m_CreatedElement = (Element) cur;
                }

                if ( WSConstants.EXPIRES_LN.equals( cur.getLocalName() )
                    && WSConstants.WSU_NS.equals( cur.getNamespaceURI() ) )
                {
                    this.m_ExpiresElement = (Element) cur;
                }
            }
        }

        if ( m_CreatedElement == null )
        {
            String warning = "No Created Element in Timestamp detected";
            LOG.warn( warning );
            throw new IllegalArgumentException( warning );
        }

        if ( m_ExpiresElement == null )
        {
            String warning = "No expires Element in Timestamp detected";
            LOG.warn( warning );
            throw new IllegalArgumentException( warning );
        }
    }

    @Override
    public void updateTimeStamp( Document doc )
    {
        TimestampUpdateHelper helper = null;

        if ( null != getCreatedPayload() && null != getExpiresPayload() )
        {
            Element ceatedPay = DomUtilities.findCorrespondingElement( doc, getCreatedPayload() );
            Element expPay = DomUtilities.findCorrespondingElement( doc, getExpiresPayload() );

            try
            {
                helper = new TimestampUpdateHelper( ceatedPay.getTextContent(), expPay.getTextContent() );
            }
            catch ( ParseException ex )
            {
                String warning = "Timestampformat could not be handled";
                LOG.warn( warning );
                try
                {
                    throw new InvalidPayloadException( warning );
                }
                catch ( InvalidPayloadException ex1 )
                {
                    LOG.error(ex);
                }
            }
            ceatedPay.setTextContent( helper.getStart() );
            expPay.setTextContent( helper.getEnd() );
        }
    }

    @Override
    public void setTimeStampPayloads( Element pay )
    {
        setDetectionPayElement( pay );
        for ( Node cur = getDetectionPayElement().getFirstChild(); cur != null; cur = cur.getNextSibling() )
        {
            if ( cur.getNodeType() == Node.ELEMENT_NODE )
            {
                if ( WSConstants.CREATED_LN.equals( cur.getLocalName() )
                    && WSConstants.WSU_NS.equals( cur.getNamespaceURI() ) )
                {
                    setCreatedPayload( (Element) cur );
                }

                if ( WSConstants.EXPIRES_LN.equals( cur.getLocalName() )
                    && WSConstants.WSU_NS.equals( cur.getNamespaceURI() ) )
                {
                    setExpiresPayload( (Element) cur );
                }
            }
        }
    }

    public Element getCreatedElement()
    {
        return m_CreatedElement;
    }

    public void setCreatedElement( Element createdElement )
    {
        this.m_CreatedElement = createdElement;
    }

    public Element getExpiresElement()
    {
        return m_ExpiresElement;
    }

    public void setExpiresElement( Element expiresElement )
    {
        this.m_ExpiresElement = expiresElement;
    }

    public Element getCreatedPayload()
    {
        return m_CreatedPayload;
    }

    public void setCreatedPayload( Element createdPayload )
    {
        this.m_CreatedPayload = createdPayload;
    }

    public Element getExpiresPayload()
    {
        return m_ExpiresPayload;
    }

    public void setExpiresPayload( Element expiresPayload )
    {
        this.m_ExpiresPayload = expiresPayload;
    }

    public void setCreatedValue( String createdVal )
    {
        this.m_CreatedElement.setTextContent( createdVal );
    }

    public void setExpiresValue( String expiresVal )
    {
        this.m_ExpiresElement.setTextContent( expiresVal );
    }
}
