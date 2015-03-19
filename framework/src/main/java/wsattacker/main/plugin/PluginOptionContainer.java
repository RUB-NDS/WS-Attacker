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
package wsattacker.main.plugin;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.apache.log4j.Logger;
import org.jdesktop.beans.AbstractBean;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;

/**
 * A container class for holding and managing plugin options
 * 
 * @author Christian Mainka
 */
public class PluginOptionContainer
    extends AbstractBean
    implements Iterable<AbstractOption>, Serializable
{

    private static final long serialVersionUID = 2L;

    final private static Logger LOG = Logger.getLogger( PluginOptionContainer.class );

    public static final String PROP_OPTIONS = "options";

    public static final String PROP_OWNERPLUGIN = "ownerPlugin";

    private List<AbstractOption> options = new ArrayList<AbstractOption>();

    private AbstractPlugin ownerPlugin;

    public PluginOptionContainer()
    {
        super();
    }

    public PluginOptionContainer( AbstractPlugin ownerPlugin )
    {
        this();
        this.ownerPlugin = ownerPlugin;
    }

    /**
     * Get the value of ownerPlugin
     * 
     * @return the value of ownerPlugin
     */
    public AbstractPlugin getOwnerPlugin()
    {
        return ownerPlugin;
    }

    /**
     * Set the value of ownerPlugin
     * 
     * @param ownerPlugin new value of ownerPlugin
     */
    public void setOwnerPlugin( AbstractPlugin ownerPlugin )
    {
        AbstractPlugin oldOwnerPlugin = this.ownerPlugin;
        this.ownerPlugin = ownerPlugin;
        firePropertyChange( PROP_OWNERPLUGIN, oldOwnerPlugin, ownerPlugin );
    }

    /**
     * Get all options. This List is unmodifable!
     * 
     * @return the value of options
     */
    public List<AbstractOption> getOptions()
    {
        return Collections.unmodifiableList( options );
    }

    /**
     * Set all options at once, overwrite the old options completely.
     * 
     * @param options new value of options
     */
    public synchronized void setOptions( List<AbstractOption> options )
    {
        synchronizeCollectionForAllPlugins( options );
        List<AbstractOption> oldOptions = new ArrayList<AbstractOption>( this.options );
        this.options = new ArrayList<AbstractOption>( options );
        List<AbstractOption> newOptions = getOptions();
        fireIndexedPropertyChange( PROP_OPTIONS, 0, oldOptions, newOptions );
    }

    /**
     * Get the value of options at specified index
     * 
     * @param index
     * @return the value of options at specified index
     */
    public AbstractOption getOptions( int index )
    {
        return this.options.get( index );
    }

    /**
     * Set the value of options at specified index. Note that the old option is overwritten.
     * 
     * @param index
     * @param newOption new value of options at specified index
     */
    public synchronized void setOptions( int index, AbstractOption newOption )
    {
        AbstractOption oldOption = this.options.set( index, newOption );
        fireIndexedPropertyChange( PROP_OPTIONS, index, oldOption, newOption );
    }

    /**
     * Adds an AbstractOption to the container
     * 
     * @param option
     * @return the container (for multi adding)
     */
    public void add( AbstractOption option )
    {
        add( options.size(), option );
    }

    /**
     * Adds an AbstractOption to the container at a specified position
     * 
     * @param position
     * @param option
     * @return the container (for multi adding)
     */
    public synchronized void add( int position, AbstractOption option )
    {
        AbstractOption search = getByName( option.getName() );
        if ( search != null )
        {
            LOG.warn( "Trying to add an option with an existing name... option not added! Please consult the plugin maintainer!" );
        }
        else
        {
            List<AbstractOption> oldOptions = new ArrayList<AbstractOption>( options );
            options.add( position, option );
            option.setCollection( this );
            List<AbstractOption> newOptions = getOptions();
            fireIndexedPropertyChange( PROP_OPTIONS, position, oldOptions, newOptions );
        }
    }

    /**
     * removes an AbstractOption from the container
     * 
     * @param option
     * @return the container (for multi adding)
     */
    public synchronized void remove( AbstractOption option )
    {
        if ( options.contains( option ) )
        {
            int position = indexOf( option );
            List<AbstractOption> oldOptions = new ArrayList<AbstractOption>( options );
            options.remove( option );
            List<AbstractOption> newOptions = getOptions();
            option.setCollection( null );
            fireIndexedPropertyChange( PROP_OPTIONS, position, oldOptions, newOptions );
        }
    }

    public boolean contains( AbstractOption o )
    {
        return options.contains( o );
    }

    public synchronized void clear()
    {
        List<AbstractOption> oldOptions = new ArrayList<AbstractOption>( options );
        options.clear();
        List<AbstractOption> newOptions = getOptions();
        fireIndexedPropertyChange( PROP_OPTIONS, 0, oldOptions, newOptions );
    }

    /**
     * Gets an option by its index
     * 
     * @param index
     * @return the option
     */
    public AbstractOption getByIndex( int index )
    {
        return getOptions( index );
    }

    /**
     * Gets an option by its name
     * 
     * @param name
     * @return the option
     */
    public AbstractOption getByName( String name )
    {
        AbstractOption result = null;
        for ( AbstractOption option : options )
        {
            if ( option.getName().equals( name ) )
            {
                result = option;
            }
        }
        return result;
    }

    /**
     * gets the index of an option this can be used for adding options after/before another
     * 
     * @param option
     * @return the index of the option
     */
    public int indexOf( AbstractOption option )
    {
        return options.indexOf( option );
    }

    /**
     * count the contained options
     * 
     * @return size
     */
    public int size()
    {
        return options.size();
    }

    @Override
    public Iterator<AbstractOption> iterator()
    {
        return options.iterator();
    }

    public AbstractOption[] getOptionArray()
    {
        return options.toArray( new AbstractOption[] {} );
    }

    private void synchronizeCollectionForAllPlugins( List<AbstractOption> newOptions )
    {
        // new added options must
        for ( AbstractOption o : newOptions )
        {
            if ( !options.contains( o ) )
            {
                o.setCollection( this );
            }
        }
        for ( AbstractOption o : this.options )
        {
            if ( !newOptions.contains( o ) )
            {
                o.setCollection( null );
            }
        }
    }
}
