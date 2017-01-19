/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.plugin.intelligentdos.postanalyze;

import java.awt.Window;
import wsattacker.main.composition.plugin.PluginFunctionInterface;
import wsattacker.plugin.intelligentdos.ui.dialog.Result_NB;
import wsattacker.plugin.intelligentdos.worker.IntelligentDoSWorker;

/**
 * @author Christian Altmeier
 */
public class IntelligentDoSPostAnalyzeFunction
    implements PluginFunctionInterface
{

    private Result_NB result;

    private final IntelligentDoSWorker intelligentDoSWorker;

    public IntelligentDoSPostAnalyzeFunction( IntelligentDoSWorker intelligentDoSWorker )
    {
        if ( intelligentDoSWorker == null )
        {
            throw new IllegalArgumentException( "intelligentDoSWorker may not be null!" );
        }
        this.result = null;
        this.intelligentDoSWorker = intelligentDoSWorker;
    }

    @Override
    public String getName()
    {
        return "Result";
    }

    @Override
    public boolean isEnabled()
    {
        return intelligentDoSWorker.isFinished();
    }

    @Override
    public Window getGuiWindow()
    {
        if ( result == null )
        {
            result =
                new Result_NB( "WS-Attacker - Intelligent Denial-of-Service Attack Results",
                               intelligentDoSWorker.getResult() );
        }
        return result;
    }

}
