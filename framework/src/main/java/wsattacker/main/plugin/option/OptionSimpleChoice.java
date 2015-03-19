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
package wsattacker.main.plugin.option;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import wsattacker.main.composition.plugin.option.AbstractOptionChoice;

public class OptionSimpleChoice
    extends AbstractOptionChoice
{

    private static final long serialVersionUID = 1L;

    public static final String PROP_CHOICES = "choices";

    public static final String PROP_SELECTEDINDEX = "selectedIndex";

    public static final String PROP_SELECTEDASSTRING = "selectedAsString";

    private List<String> choices;

    private int selected;

    public OptionSimpleChoice( String name, String description )
    {
        this( name, new ArrayList<String>(), 0 );
        choices.add( "No hoices available" );
    }

    public OptionSimpleChoice( String name, List<String> choices, int selected )
    {
        this( name, choices, selected, "" );
    }

    public OptionSimpleChoice( String name, List<String> choices, int selected, String description )
    {
        super( name, description );
        this.choices = choices;
        if ( ( selected >= 0 ) && ( selected < choices.size() ) )
        {
            this.selected = selected;
        }
    }

    @Override
    public boolean isValid( int choice )
    {
        return ( ( choice >= 0 ) && ( choice < choices.size() ) );
    }

    @Override
    public boolean isValid( String value )
    {
        return choices.contains( value );
    }

    @Override
    public void parseValue( String value )
    {
        if ( isValid( value ) )
        {
            setSelectedIndex( choices.indexOf( value ) );
        }
        else
        {
            throw new IllegalArgumentException( String.format( "isValid(\"%s\") returned false", value ) );
        }
    }

    @Override
    public String getSelectedAsString()
    {
        return choices.get( selected );
    }

    @Override
    public List<String> getChoices()
    {
        return Collections.unmodifiableList( choices );
    }

    @Override
    public void setSelectedAsString( String value )
    {
        parseValue( value );
    }

    @Override
    public void setSelectedIndex( int index )
    {
        if ( isValid( index ) )
        {
            int oldSelected = this.selected;
            String oldString = getValueAsString();
            this.selected = index;
            String newString = getValueAsString();
            firePropertyChange( PROP_SELECTEDINDEX, oldSelected, selected );
            firePropertyChange( PROP_SELECTEDASSTRING, oldString, newString );
        }
    }

    @Override
    public int getSelectedIndex()
    {
        return selected;
    }

    @Override
    public void setChoices( List<String> choices )
    {
        java.util.List<java.lang.String> oldChoices = this.choices;
        this.choices = choices;
        firePropertyChange( PROP_CHOICES, oldChoices, choices );
    }
}
