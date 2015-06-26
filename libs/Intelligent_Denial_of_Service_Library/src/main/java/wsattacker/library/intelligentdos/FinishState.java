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
package wsattacker.library.intelligentdos;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;

/**
 * @author Christian Altmeier
 */
public class FinishState
    implements DoSState
{
    @Override
    public String getName()
    {
        return "finish state";
    }

    @Override
    public void update( IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {
        // nothing may not be done

    }

    @Override
    public void updateTestProbes( Metric metric )
    {
        // nothing may not be done

    }

}
