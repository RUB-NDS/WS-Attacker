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
package wsattacker.plugin.dos.dosExtension.mvc;

import javax.swing.SwingUtilities;
import wsattacker.plugin.dos.dosExtension.abstractPlugin.AbstractDosPlugin;
import wsattacker.plugin.dos.dosExtension.function.postanalyze.DOSPostAnalyzeFunction;
import wsattacker.plugin.dos.dosExtension.gui.DosResultJFrame;
import wsattacker.plugin.dos.dosExtension.gui.GuiAttackStatusRunnable;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * entry point to WS-Attacker DOS-Extension performs the DOS-Attack using the MVC pattern returns to caller only if
 * certain states in model are set: - - -
 * 
 * @return retunrs entire AttackModel with all states, data and attackresults!
 */
public class AttackMVC
{
    public static AttackModel runDosAttack( AttackModel attackModel )
    {
        // Call GUI via seperate runnabele -> guarantees that it runs in EDT
        GuiAttackStatusRunnable myGuiRunnable = new GuiAttackStatusRunnable( attackModel );
        SwingUtilities.invokeLater( myGuiRunnable );

        // constantly check wheater attack is still running or already finished!
        while ( !attackModel.isAttackFinished() )
        {
            try
            {
                Thread.sleep( 1000 );
            }
            catch ( InterruptedException e )
            {
                // TODO [CHAL 2014-01-02] Use Logger instead of System.out ...
                return attackModel;
            }
        }

        return attackModel;
    }

    public static AttackModel runDosAttack( AbstractDosPlugin plugin )
    {
        // unique AttackModel
        // - hold entire Attackdata
        // - provides all attack methods
        AttackModel model = new AttackModel( plugin );

        AttackModel runDosAttack = runDosAttack( model );

        // Call new JFrame-GUI
        // ONLY if autoFinalizeSwitch is turned to manuel [== false]!!
        DosResultJFrame dosResultFrame = new DosResultJFrame( runDosAttack );
        dosResultFrame.setLocationRelativeTo( null );
        dosResultFrame.setVisible( !runDosAttack.isAutoFinalizeSwitch() );

        // update PostAnalyze function with full model!
        DOSPostAnalyzeFunction b = (DOSPostAnalyzeFunction) plugin.getPluginFunctions( 0 );
        b.setAttackModel( runDosAttack );
        b.setAttackResultJFrame( dosResultFrame );

        return runDosAttack;
    }
}
