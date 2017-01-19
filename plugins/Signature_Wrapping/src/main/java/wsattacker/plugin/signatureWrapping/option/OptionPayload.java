/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2011 Christian Mainka
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
package wsattacker.plugin.signatureWrapping.option;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.plugin.signatureWrapping.gui.OptionPayloadGUI_NB;

/**
 * The OptionPayload class hold gives a connection between the signed element and the payload element.
 */
public class OptionPayload
    extends AbstractOption
    implements PropertyChangeListener
{

    public static final String PROP_PAYLOAD = "payload";

    final static private Logger LOG = Logger.getLogger( OptionPayload.class );

    private final Payload payload;

    public static final String PROP_VALUE = "value";

    public static final String PROP_WORKINGXPATH = "workingXPath";

    /**
     * Get the value of value
     * 
     * @return the value of value
     */
    public String getValue()
    {
        return ( payload == null ) ? "" : payload.getValue();
    }

    /**
     * Constructor for the OptionPayload.
     * 
     * @param referringElement : Reference to the Reference element.
     * @param name : Name of the option.
     * @param signedElement : The signed element. This is usefull, if the Reference element selects more than one signed
     *            element (e.g. when using XPath).
     * @param description . Description of the option.
     */
    public OptionPayload( Payload payload )
    {
        super( "Payload Option", "This payload will be placed at the position of the signed element." );
        if ( payload.getSignedElement() != null )
        {
            String name = String.format( "Payload for %s", payload.getSignedElement().getNodeName() );
            setName( name );
            String description = DomUtilities.getFastXPath( payload.getSignedElement() );
            setDescription( description );
        }
        this.payload = payload;
        payload.addPropertyChangeListener( this );
    }

    /**
     * Does this option has any payload?
     * 
     * @return
     */
    public boolean hasPayload()
    {
        return ( payload == null ) ? false : payload.hasPayload();
    }

    /**
     * Is the signed element a Timestamp element?
     * 
     * @return
     */
    public boolean isTimestamp()
    {
        return ( payload == null ) ? false : payload.isTimestamp();
    }

    /**
     * Set if the signed element is a Timestamp element.
     * 
     * @param isTimestamp
     */
    public void setTimestamp( boolean isTimestamp )
    {
        payload.setTimestamp( isTimestamp );
    }

    @Override
    public boolean isValid( String value )
    {
        return payload.isValid( value );
    }

    /**
     * Returns the GUI component for the OptionPayload used by the WS-Attacker.
     */
    @Override
    public OptionGUI createOptionGUI()
    {
        LOG.trace( getName() + ": " + "GUI Requested" );
        return new OptionPayloadGUI_NB( this );
    }

    /**
     * The the value for the payload.
     */
    @Override
    public void parseValue( String value )
    {
        setValue( value );
    }

    /**
     * Set the value of value
     * 
     * @param value new value of value
     */
    public void setValue( String value )
    {
        boolean isValid = isValid( value );
        if ( isValid )
        {
            String oldValue = getValue();
            payload.setValue( value );
            String newValue = getValue();
            firePropertyChange( PROP_VALUE, oldValue, newValue );
            LOG.info( String.format( "Saving Payload Value: %s", newValue ) );
        }
        else
        {
            throw new IllegalArgumentException( String.format( "isValid(\"%s\" returned false", value ) );
        }
    }

    @Override
    public String getValueAsString()
    {
        return getValue();
    }

    /**
     * Get the value of workingXPath
     * 
     * @return the value of workingXPath
     */
    public String getWorkingXPath()
    {
        String result;
        if ( payload != null && payload.getReferringElement() != null )
        {
            result = payload.getReferringElement().getXPath();
        }
        else
        {
            result = "";
        }
        return result;
    }

    /**
     * Set the value of workingXPath
     * 
     * @param workingXPath new value of workingXPath
     */
    public void setWorkingXPath( String workingXPath )
    {
        String oldWorkingXPath = getWorkingXPath();
        payload.getReferringElement().setXPath( workingXPath );
        firePropertyChange( PROP_WORKINGXPATH, oldWorkingXPath, workingXPath );
    }

    @Override
    public void propertyChange( PropertyChangeEvent pce )
    {
        final String property = pce.getPropertyName();
        if ( Payload.PROP_TIMESTAMP.equals( property ) )
        {
            firePropertyChange( pce );
        }
        else if ( Payload.PROP_PAYLOADELEMENT.equals( property ) )
        {
            String oldValue = DomUtilities.domToString( (Element) pce.getOldValue() );
            String newValue = DomUtilities.domToString( (Element) pce.getNewValue() );
            firePropertyChange( PROP_VALUE, oldValue, newValue );
        }
    }
}
