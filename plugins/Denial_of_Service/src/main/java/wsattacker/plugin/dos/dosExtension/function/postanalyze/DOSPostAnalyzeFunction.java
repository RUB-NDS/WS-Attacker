/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.function.postanalyze;

import java.awt.Window;

import javax.swing.JDialog;

import wsattacker.main.composition.plugin.PluginFunctionInterface;
import wsattacker.plugin.dos.dosExtension.gui.DosResultJFrame;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

public class DOSPostAnalyzeFunction
    implements PluginFunctionInterface
{

    private AttackModel model;

    private DosResultJFrame dosResultFrame;

    public DOSPostAnalyzeFunction()
    {
        this.model = null;
        this.dosResultFrame = null;
    }

    public void setAttackModel( AttackModel model )
    {
        this.model = model;
    }

    public void setAttackResultJFrame( DosResultJFrame dosResultFrame )
    {
        this.dosResultFrame = dosResultFrame;
    }

    @Override
    public String getName()
    {
        return "View Attack Result";
    }

    @Override
    public boolean isEnabled()
    {
        return model != null && model.isAttackFinished();
    }

    @Override
    public Window getGuiWindow()
    {
        if ( model != null )
        {
            if ( dosResultFrame == null )
            {
                System.err.println( "no ResultJFrame set..." );
            }
            return dosResultFrame;
        }
        else
        {
            JDialog resultDialog = new JDialog();
            resultDialog.setTitle( "The attack is not in a finished state!\n"
                + "Therefore no result GUI is available yet." );
            resultDialog.setSize( 200, 200 );
            resultDialog.setModal( true );
            resultDialog.setVisible( true );
            return resultDialog;
        }
    }
}
