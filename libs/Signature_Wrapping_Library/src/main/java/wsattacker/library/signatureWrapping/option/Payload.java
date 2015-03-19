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
package wsattacker.library.signatureWrapping.option;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.text.ParseException;
import java.util.*;
import org.apache.log4j.Logger;
import org.apache.ws.security.WSConstants;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.signature.ReferringElementInterface;
import wsattacker.library.signatureWrapping.util.timestamp.TimestampUpdateHelper;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * The Payload class hold gives a connection between the signed element and the payload element.
 */
public class Payload
{

    public static final String PROP_TIMESTAMP = "timestamp";

    public static final String PROP_WRAPONLY = "wrapOnly";

    public static final String PROP_PAYLOADELEMENT = "payloadElement";

    public static final String PROP_SIGNEDELEMENT = "signedElement";

    public static final String PROP_REFERRINGELEMENT = "referringElement";

    private static final Logger LOG = Logger.getLogger( Payload.class );

    private static final long serialVersionUID = 2L;

    private static final String ASSERTION = "Assertion";

    private static final String CONDITIONS = "Conditions";

    private static final String NOTBEFORE = "NotBefore";

    private static final String NOTONORAFTER = "NotOnOrAfter";

    private boolean timestamp = false, wrapOnly = false;

    private Element payloadElement;

    private Element signedElement;

    private ReferringElementInterface referringElement;

    private final transient PropertyChangeSupport propertyChangeSupport = new java.beans.PropertyChangeSupport( this );

    public Payload()
    {
    }

    /**
     * Constructor for the Payload.
     * 
     * @param referringElement : Reference to the Reference element.
     * @param name : Name of the option.
     * @param signedElement : The signed element. This is usefull, if the Reference element selects more than one signed
     *            element (e.g. when using XPath).
     * @param description . Description of the option.
     */
    public Payload( ReferringElementInterface referringElement, Element signedElement )
    {
        setReferringElement( referringElement );
        setSignedElement( signedElement );
    }

    /**
     * Does this option has any payload?
     * 
     * @return
     */
    public boolean hasPayload()
    {
        boolean hasPayload = true;
        if ( payloadElement == null )
        {
            hasPayload = false;
        }
        else if ( payloadElement.isEqualNode( signedElement ) )
        {
            hasPayload = false;
        }
        return hasPayload;
        // return (payloadElement != null);
    }

    /**
     * Returns the payload element. If it is a Timestamp element, automatically an updated one is returned.
     * 
     * @return the payload elemeent.
     * @throws InvalidPayloadException
     */
    public Element getPayloadElement()
        throws InvalidPayloadException
    {
        // This is now needed for the case: wrapOnly
        // if (payloadElement == null) {
        // payloadElement = (Element) signedElement.cloneNode(true);
        // }
        Element retr = payloadElement;
        // If it is a timestamp, we need to create a valid one!
        if ( timestamp )
        {
            // Element timestamp = (Element)
            // originalDocument.getDocumentElement().cloneNode(true);
            Element timestamp = (Element) signedElement.cloneNode( true );
            if ( timestamp.getLocalName().equals( WSConstants.TIMESTAMP_TOKEN_LN ) )
            {
                // CASE: WSU:TIMESTAMP
                // 1) Find created and expires Element
                // ////////////////////////////////////
                Element createdElement = null, expiresElement = null;
                for ( Node cur = timestamp.getFirstChild(); cur != null; cur = cur.getNextSibling() )
                {
                    if ( cur.getNodeType() == Node.ELEMENT_NODE )
                    {
                        // Case Created
                        if ( WSConstants.CREATED_LN.equals( cur.getLocalName() )
                            && WSConstants.WSU_NS.equals( cur.getNamespaceURI() ) )
                        {
                            createdElement = (Element) cur;
                        } // Case Exires
                        else if ( WSConstants.EXPIRES_LN.equals( cur.getLocalName() )
                            && WSConstants.WSU_NS.equals( cur.getNamespaceURI() ) )
                        {
                            expiresElement = (Element) cur;
                        }
                    }
                }
                if ( createdElement == null )
                {
                    String warning = "Could not find Created Element in Timestamp";
                    LOG.warn( warning );
                    throw new InvalidPayloadException( warning );
                }
                if ( expiresElement == null )
                {
                    String warning = "Could not find Expires Element in Timestamp";
                    LOG.warn( warning );
                    throw new InvalidPayloadException( warning );
                }
                TimestampUpdateHelper helper;
                try
                {
                    helper =
                        new TimestampUpdateHelper( createdElement.getTextContent(), expiresElement.getTextContent() );
                }
                catch ( ParseException ex )
                {
                    String warning = "Timestampformat could not be handled";
                    LOG.warn( warning );
                    throw new InvalidPayloadException( warning );
                }
                createdElement.setTextContent( helper.getStart() );
                expiresElement.setTextContent( helper.getEnd() );
                retr = timestamp;
            }
            else if ( timestamp.getLocalName().equals( ASSERTION ) )
            {
                // CASE 2: SAML ASSERTION

                List<Element> conditionElementList = DomUtilities.findChildren( timestamp, CONDITIONS, null );
                if ( conditionElementList.isEmpty() )
                {
                    String warning = "Could not find the Element <" + CONDITIONS + "/>";
                    LOG.warn( warning );
                    throw new InvalidPayloadException( warning );
                }
                if ( conditionElementList.size() > 1 )
                {
                    String warning = "There are " + conditionElementList.size() + " <" + CONDITIONS + "/> Elements";
                    LOG.warn( warning );
                    throw new InvalidPayloadException( warning );
                }

                Element conditionElement = conditionElementList.get( 0 );

                Attr notBefore = conditionElement.getAttributeNode( NOTBEFORE );
                if ( notBefore == null )
                {
                    String warning = "Could not find '" + NOTBEFORE + "' Attribute";
                    LOG.warn( warning );
                    throw new InvalidPayloadException( warning );
                }

                Attr notOnOrAfter = conditionElement.getAttributeNode( NOTONORAFTER );
                if ( notOnOrAfter == null )
                {
                    String warning = "Could not find '" + NOTONORAFTER + "' Attribute";
                    LOG.warn( warning );
                    throw new InvalidPayloadException( warning );
                }

                TimestampUpdateHelper helper;
                try
                {
                    helper = new TimestampUpdateHelper( notBefore.getTextContent(), notOnOrAfter.getTextContent() );
                }
                catch ( ParseException ex )
                {
                    String warning = "Timestampformat could not be handled";
                    LOG.warn( warning );
                    throw new InvalidPayloadException( warning );
                }
                notBefore.setTextContent( helper.getStart() );
                notOnOrAfter.setTextContent( helper.getEnd() );
                retr = timestamp;
            }
        }
        return retr;
    }

    /**
     * Return the signed element.
     * 
     * @return
     */
    public Element getSignedElement()
    {
        return signedElement;
    }

    /**
     * Return the Reference element.
     * 
     * @return
     */
    public ReferringElementInterface getReferringElement()
    {
        return referringElement;
    }

    /**
     * Is the signed element a Timestamp element?
     * 
     * @return
     */
    public boolean isTimestamp()
    {
        return timestamp;
    }

    /**
     * Set if the signed element is a Timestamp element.
     * 
     * @param timestamp
     */
    public void setTimestamp( boolean timestamp )
    {
        log().trace( "Payload.setTimestamp() setTimestamp = " + timestamp );
        boolean oldTimestamp = this.timestamp;
        this.timestamp = timestamp;
        propertyChangeSupport.firePropertyChange( PROP_TIMESTAMP, oldTimestamp, timestamp );
    }

    public void setPayloadElement( Element payloadElement )
    {
        org.w3c.dom.Element oldPayloadElement = this.payloadElement;
        this.payloadElement = payloadElement;
        propertyChangeSupport.firePropertyChange( PROP_PAYLOADELEMENT, oldPayloadElement, payloadElement );
    }

    public void setSignedElement( Element signedElement )
    {
        org.w3c.dom.Element oldSignedElement = this.signedElement;
        this.signedElement = signedElement;
        propertyChangeSupport.firePropertyChange( PROP_SIGNEDELEMENT, oldSignedElement, signedElement );
        if ( signedElement != null )
        {
            setPayloadElement( (Element) signedElement.cloneNode( true ) );
            setTimestamp( detectTimestamp() );
        }
    }

    public void setReferringElement( ReferringElementInterface referringElement )
    {
        wsattacker.library.signatureWrapping.util.signature.ReferringElementInterface oldReferringElement =
            this.referringElement;
        this.referringElement = referringElement;
        propertyChangeSupport.firePropertyChange( PROP_REFERRINGELEMENT, oldReferringElement, referringElement );
    }

    private Logger log()
    {
        return Logger.getLogger( getClass() );
    }

    public boolean isValid( String value )
    {
        boolean isValid = true;
        if ( value.length() >= 3 )
        {
            try
            {
                DomUtilities.stringToDom( value );
            }
            catch ( Exception e )
            {
                log().error( "Payload.isValid() Error: " + e.getLocalizedMessage() );
                isValid = false;
            }
        }
        return isValid;
    }

    /**
     * The the value for the payload.
     */
    public void setValue( String value )
        throws IllegalArgumentException
    {
        if ( isValid( value ) )
        {
            try
            {
                setPayloadElement( DomUtilities.stringToDom( value ).getDocumentElement() );
            }
            catch ( Exception e )
            {
                throw new IllegalArgumentException( e );
            }
            // this.value = value;
            log().info( "Has payload? " + hasPayload() );
        }
    }

    /**
     * The the value for the payload.
     */
    public void removeValue()
        throws IllegalArgumentException
    {
        setPayloadElement( signedElement );
        log().info( "Has payload? " + hasPayload() );
    }

    private boolean detectTimestamp()
    {
        boolean isT = signedElement.getLocalName().equals( WSConstants.TIMESTAMP_TOKEN_LN );
        // TODO: Think about detection of SAML Timestamps
        // if (!isT) {
        // String elementLocalName = this.signedElement.getLocalName();
        // if (elementLocalName.equals(getASSERTION())) {
        // isT = !DomUtilities.findChildren(signedElement, CONDITIONS,
        // null).isEmpty();
        // }
        // }
        return isT;
    }

    public String getValue()
    {
        // return value;
        return DomUtilities.domToString( payloadElement );
    }

    public boolean isWrapOnly()
    {
        return wrapOnly;
    }

    public void setWrapOnly( boolean wrapOnly )
    {
        boolean oldWrapOnly = this.wrapOnly;
        this.wrapOnly = wrapOnly;
        propertyChangeSupport.firePropertyChange( PROP_WRAPONLY, oldWrapOnly, wrapOnly );
    }

    /**
     * Add PropertyChangeListener.
     * 
     * @param listener
     */
    public void addPropertyChangeListener( final PropertyChangeListener listener )
    {
        propertyChangeSupport.addPropertyChangeListener( listener );
    }

    /**
     * Add PropertyChangeListener.
     * 
     * @param propertyName
     * @param listener
     */
    public void addPropertyChangeListener( final String propertyName, final PropertyChangeListener listener )
    {
        propertyChangeSupport.addPropertyChangeListener( propertyName, listener );
    }

    /**
     * Remove PropertyChangeListener.
     * 
     * @param listener
     */
    public void removePropertyChangeListener( final PropertyChangeListener listener )
    {
        propertyChangeSupport.removePropertyChangeListener( listener );
    }

    /**
     * Remove PropertyChangeListener.
     * 
     * @param propertyName
     * @param listener
     */
    public void removePropertyChangeListener( final String propertyName, final PropertyChangeListener listener )
    {
        propertyChangeSupport.removePropertyChangeListener( propertyName, listener );
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append( "Payload{" );
        sb.append( "signedElement=" ).append( signedElement );
        sb.append( ", payloadElement=" ).append( payloadElement );
        sb.append( ", referringElement=" ).append( referringElement );
        sb.append( ", timestamp=" ).append( timestamp );
        sb.append( ", wrapOnly=" ).append( wrapOnly );
        sb.append( '}' );
        return sb.toString();
    }
}
