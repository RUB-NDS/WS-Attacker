/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2014 Christian Mainka
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
package wsattacker.http.transport;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;

public class HttpHeader
{
    public static final String PROP_VALUE = "value";

    public static final String PROP_NAME = "name";

    private String name = "HeaderName";

    private String value = "HeaderValue";

    private final transient PropertyChangeSupport propertyChangeSupport = new PropertyChangeSupport( this );

    public HttpHeader()
    {
    }

    public HttpHeader( String name, String value )
    {
        this();
        this.name = name;
        this.value = value;
    }

    public String getValue()
    {
        return value;
    }

    public void setValue( String value )
    {
        String oldValue = this.value;
        this.value = value;
        propertyChangeSupport.firePropertyChange( PROP_VALUE, oldValue, value );
    }

    public String getName()
    {
        return name;
    }

    public void setName( String name )
    {
        String oldName = this.name;
        this.name = name;
        propertyChangeSupport.firePropertyChange( PROP_NAME, oldName, name );
    }

    public void addPropertyChangeListener( PropertyChangeListener listener )
    {
        propertyChangeSupport.addPropertyChangeListener( listener );
    }

    public void removePropertyChangeListener( PropertyChangeListener listener )
    {
        propertyChangeSupport.removePropertyChangeListener( listener );
    }

    @Override
    public String toString()
    {
        return name + ": " + value;
    }

}
