/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.main.composition;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;

public class AbstractBean
{

    private transient final PropertyChangeSupport propertyChangeSupport = new PropertyChangeSupport( this );

    /**
     * Add PropertyChangeListener.
     * 
     * @param listener
     */
    final public void addPropertyChangeListener( PropertyChangeListener listener )
    {
        propertyChangeSupport.addPropertyChangeListener( listener );
    }

    final public void addPropertyChangeListener( String propertyName, PropertyChangeListener listener )
    {
        propertyChangeSupport.addPropertyChangeListener( propertyName, listener );
    }

    /**
     * Remove PropertyChangeListener.
     * 
     * @param listener
     */
    final public void removePropertyChangeListener( PropertyChangeListener listener )
    {
        propertyChangeSupport.removePropertyChangeListener( listener );
    }

    final public void removePropertyChangeListener( String propertyName, PropertyChangeListener listener )
    {
        propertyChangeSupport.removePropertyChangeListener( propertyName, listener );
    }

    public final PropertyChangeListener[] getPropertyChangeListeners()
    {
        return propertyChangeSupport.getPropertyChangeListeners();
    }

    public final PropertyChangeListener[] getPropertyChangeListeners( String propertyName )
    {
        return propertyChangeSupport.getPropertyChangeListeners( propertyName );
    }

    protected final void firePropertyChange( String propertyName, Object oldValue, Object newValue )
    {
        propertyChangeSupport.firePropertyChange( propertyName, oldValue, newValue );
    }

    protected final void firePropertyChange( PropertyChangeEvent evt )
    {
        propertyChangeSupport.firePropertyChange( evt );
    }

    protected final void fireIndexedPropertyChange( String propertyName, int index, Object oldValue, Object newValue )
    {
        propertyChangeSupport.fireIndexedPropertyChange( propertyName, index, oldValue, newValue );
    }

    protected final boolean hasPropertyChangeListeners( String propertyName )
    {
        return propertyChangeSupport.hasListeners( propertyName );
    }
}
