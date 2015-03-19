/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Christian Mainka
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
package wsattacker.plugin.optionsTester;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.Arrays;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginOptionContainer;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionSimpleChoice;
import wsattacker.main.plugin.option.OptionSimpleMultiFiles;
import wsattacker.main.plugin.option.OptionSimpleVarchar;

public class OptionsTesterPlugin
    extends AbstractPlugin
    implements PropertyChangeListener
{

    private static final long serialVersionUID = 1L;

    private OptionSimpleVarchar theChoice;

    private OptionSimpleChoice choice;

    @Override
    public void initializePlugin()
    {
        PluginOptionContainer c = getPluginOptions();
        // String[] varcharoptions = new String[] {"First", "Second", "Third",
        // "Forth"};
        // for (String name : varcharoptions) {
        // c.add(new OptionSimpleVarchar(name + "_string", name));
        // c.add(new OptionSimpleText(name + "_text", name));
        // c.add(new OptionSimpleBoolean(name + "_bool", true));
        // }
        // OptionSimpleVarchar limited = new
        // OptionSimpleVarchar("Limited Varchar", "Value", "Testing maxLength",
        // 10);
        // c.add(limited);
        // OptionSimpleFile file = new OptionSimpleFile("File",
        // "Select a file");
        // c.add(file);
        OptionSimpleMultiFiles multiFiles =
            new OptionSimpleMultiFiles( "Multiple Files", "Select more than one filce at once" );
        c.add( multiFiles );
        // theChoice = new OptionSimpleVarchar("The Choice", "Test");
        // c.add(theChoice);
        choice = new OptionSimpleChoice( "Choice", Arrays.asList( "One", "Two", "Three" ), 0 );
        // choice.addPropertyChangeListener(this);
        c.add( choice );
        setState( PluginState.Ready );
    }

    @Override
    public String getName()
    {
        return "Option Tester Plugin";
    }

    @Override
    public String getDescription()
    {
        return "Description Test";
    }

    @Override
    public String getAuthor()
    {
        return "Option Test Author";
    }

    @Override
    public String getVersion()
    {
        return "1.0";
    }

    @Override
    public int getMaxPoints()
    {
        return 10;
    }

    @Override
    protected void attackImplementationHook( RequestResponsePair original )
    {
    }

    @Override
    public void clean()
    {
        setState( PluginState.Ready );
    }

    @Override
    public boolean wasSuccessful()
    {
        return false;
    }

    @Override
    public String[] getCategory()
    {
        return new String[] { "Test" };
    }

    @Override
    public void propertyChange( PropertyChangeEvent pce )
    {
        if ( OptionSimpleChoice.PROP_SELECTEDASSTRING.equals( pce.getPropertyName() ) )
        {
            System.out.println( "### propertyChangeEvent" );
            String value = choice.getValueAsString();
            theChoice.setValue( value != null ? value : "null" );
        }
    }
}
