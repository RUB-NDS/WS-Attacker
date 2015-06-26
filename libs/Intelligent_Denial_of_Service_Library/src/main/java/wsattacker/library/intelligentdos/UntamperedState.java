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
public class UntamperedState
    implements DoSState
{

    @Override
    public String getName()
    {
        return "untampered state";
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
            setNotPossibleState( STATE_CONTEXT );
        }
        else
        {

            STATE_CONTEXT.setCurrentUntampered( attackModel.getDurationArray() );

            if ( !STATE_CONTEXT.noFurtherIterations )
            {
                // create the first attack (tampered) don't iterate here
                STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createNewTampered( false ) );
                STATE_CONTEXT.setHasFurtherAttack( true );

                STATE_CONTEXT.setDoSState( new TamperedState() );
            }
            else
            {
                // hasFurtherAttack is already false
                STATE_CONTEXT.setDoSState( new FinishState() );
            }
        }
    }

    @Override
    public void updateTestProbes( Metric metric )
    {
        // not interesting for this state
    }

    private void setNotPossibleState( final IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        // resend current attack with recovery
        AttackModel createNewUntampered = STATE_CONTEXT.createNewUntampered( true );
        STATE_CONTEXT.setCurrentAttack( createNewUntampered );
        STATE_CONTEXT.setHasFurtherAttack( true );

        STATE_CONTEXT.setDoSState( new PossibleState() );
    }

}
