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
package wsattacker.main.composition.plugin.option;

import java.io.Serializable;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.main.composition.AbstractBean;
import wsattacker.main.plugin.PluginOptionContainer;

/**
 * Interface for a very basic option Does not have any setters except for the string parser All plugin options inherit
 * this interface
 * 
 * @author Christian Mainka
 */
public abstract class AbstractOption
    extends AbstractBean
    implements Serializable
{

    private static final long serialVersionUID = 2L;

    public static final String PROP_COLLECTION = "collection";

    public static final String PROP_NAME = "name";

    public static final String PROP_DESCRIPTION = "description";

    private PluginOptionContainer collection = null;

    private String name = "AbstractOption", description = "AbstractDescription";

    /**
     * Default constructor
     */
    public AbstractOption()
    {
        super();
    }

    /**
     * Constructor for creating an option with at least a name and a description
     * 
     * @param name
     * @param description
     */
    public AbstractOption( String name, String description )
    {
        this();
        this.name = name;
        this.description = description;
    }

    /**
     * Constructor for creating an option with a name and an empty description Each option must have a name
     * 
     * @param name
     */
    public AbstractOption( String name )
    {
        this( name, "" );
    }

    public String getName()
    {
        return name;
    }

    public void setName( String name )
    {
        String oldName = this.name;
        this.name = name;
        firePropertyChange( PROP_NAME, oldName, name );
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription( String description )
    {
        String oldDescription = this.description;
        this.description = description;
        firePropertyChange( PROP_DESCRIPTION, oldDescription, description );
    }

    public final PluginOptionContainer getCollection()
    {
        return collection;
    }

    /**
     * Each option belongs to exactly one PlugionOptionContainer This method will return it
     * 
     * @see PluginOptionContainer
     * @return
     */
    public void setCollection( PluginOptionContainer collection )
    {
        PluginOptionContainer oldCollection = this.collection;
        this.collection = collection;
        firePropertyChange( PROP_COLLECTION, oldCollection, collection );
    }

    /**
     * Each option has a isValid() method It must at least work for a String parameter, although there will be different
     * parameter types for e.g. Integer options
     * 
     * @param value
     * @return true if value is valid
     */
    public abstract boolean isValid( String value ); // only for generic proposals

    /**
     * Each option can parse a String value
     * 
     * @throws IllegalArgumentException if value is Invalid
     * @param value
     * @return true if value was valid and is set
     */
    public abstract void parseValue( String value ); // only for generic proposals

    /**
     * Each option can return a String representation of its value
     * 
     * @return
     */
    public abstract String getValueAsString(); // only for generic proposals

    @Override
    public String toString()
    {
        return String.format( "%s{name=%s, description=%s%s", getClass().getName(), name, description, '}' );
    }

    public abstract OptionGUI createOptionGUI();
}
