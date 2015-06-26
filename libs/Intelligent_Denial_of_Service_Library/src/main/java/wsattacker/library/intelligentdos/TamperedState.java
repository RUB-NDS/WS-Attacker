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
import wsattacker.library.intelligentdos.success.SuccessDecider;

/**
 * @author Christian Altmeier
 */
public class TamperedState
    extends AbstractDoSState
{
    @Override
    public String getName()
    {
        return "tampered state";
    }

    /*
     * (non-Javadoc)
     * @see state.Statelike#writeName(state.StateContext, java.lang.String)
     */
    @Override
    public void update( final IntelligentDoSLibraryImpl STATE_CONTEXT, final AttackModel attackModel )
    {
        if ( !attackModel.wasAttackExecutionSuccessful() )
        {
            STATE_CONTEXT.setDoSState( new PossibleState() );
            STATE_CONTEXT.update( attackModel );
        }
        else
        {
            SuccessDecider successDecider = STATE_CONTEXT.getSuccessDecider();

            Long[] currentTampered = attackModel.getDurationArray();
            Long[] currentUntampered = STATE_CONTEXT.getCurrentUntampered();
            boolean successful = successDecider.wasSuccessful( currentUntampered, currentTampered );

            if ( successful )
            {
                double calculateRatio = successDecider.calculateRatio( currentUntampered, currentTampered );
                double d = Math.round( calculateRatio * 100.0 ) / 100.0;

                String dName = attackModel.getDoSAttack() != null ? attackModel.getDoSAttack().getName() : "???";
                String msg = String.format( "First execution of %s was successful (ratio: %s).", dName, d );
                logger.info( msg );
                setSuccessfulState( STATE_CONTEXT );
            }
            else
            {
                continueAttacks( STATE_CONTEXT );
            }
        }
    }

    @Override
    public void updateTestProbes( Metric metric )
    {
        // not interesting for this state
    }

}
