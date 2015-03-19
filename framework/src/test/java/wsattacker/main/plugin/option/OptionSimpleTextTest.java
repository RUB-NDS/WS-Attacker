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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.main.plugin.option;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;

/**
 * @author christian
 */
public class OptionSimpleTextTest
{

    public OptionSimpleTextTest()
    {
    }

    @Test
    public void propertyChangeListenerWorking()
    {
        OptionSimpleText option = new OptionSimpleText( "TestName", "TestDescription" );
        option.addPropertyChangeListener( new PropertyChangeListener()
        {
            @Override
            public void propertyChange( PropertyChangeEvent pce )
            {
                System.out.println( "PropertyChange detected: " + pce.getPropertyName() );
            }
        } );
        option.setName( "New TestName" );
        option.setValue( "New TestValue" );

        assertThat( option.getName(), is( "New TestName" ) );
        assertThat( option.getValue(), is( "New TestValue" ) );
    }
}
