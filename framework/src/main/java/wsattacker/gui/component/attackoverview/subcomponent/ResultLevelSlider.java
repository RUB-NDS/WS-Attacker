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
package wsattacker.gui.component.attackoverview.subcomponent;

import java.util.Dictionary;
import java.util.Hashtable;
import javax.swing.JLabel;
import javax.swing.JSlider;
import wsattacker.main.plugin.result.ResultLevel;

public class ResultLevelSlider
    extends JSlider
{

    public ResultLevelSlider()
    {
        Dictionary<Integer, JLabel> labelTable = new Hashtable<Integer, JLabel>();
        ResultLevel[] levels = ResultLevel.values(); // get all result
        // levels
        int max = levels.length - 1;
        setMinimum( 0 );
        setMaximum( max );
        for ( int i = max; i >= 0; --i )
        {
            // add each to the slider
            labelTable.put( i, new JLabel( levels[i].toString() ) );
        }
        setLabelTable( labelTable );
        setPaintLabels( true );
        setSnapToTicks( true );
        setValue( max / 2 ); // set default level
    }
}
