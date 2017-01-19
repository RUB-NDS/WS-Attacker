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
import wsattacker.library.intelligentdos.common.RequestType;
import static wsattacker.library.intelligentdos.common.RequestType.UNTAMPERED;
import wsattacker.library.intelligentdos.success.SuccessDecider;

/**
 * @author Christian Altmeier
 */
public class SafetyState
    extends AbstractDoSState
{

    private AttackModel untampered = null;

    @Override
    public String getName()
    {
        return "safety state";
    }

    @Override
    public void update( IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {
        if ( !attackModel.wasAttackExecutionSuccessful() )
        {
            STATE_CONTEXT.setDoSState( new PossibleState() );
            STATE_CONTEXT.update( attackModel );
        }
        else if ( untampered == null && attackModel.getRequestType() == RequestType.UNTAMPERED )
        {
            untampered = attackModel;

            // create tampered
            STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createNewTampered( false ) );
            STATE_CONTEXT.setHasFurtherAttack( true );
        }
        else if ( untampered == null && attackModel.getRequestType() != RequestType.UNTAMPERED )
        {
            throw new IllegalStateException( "untampered is null but attack model was " + attackModel.getRequestType() );
        }
        else if ( untampered != null )
        {
            SuccessDecider successDecider = STATE_CONTEXT.getSuccessDecider();

            Long[] currentTampered = attackModel.getDurationArray();
            Long[] currentUntampered = untampered.getDurationArray();
            boolean successful = successDecider.wasSuccessful( currentUntampered, currentTampered );

            if ( successful )
            {
                double calculateRatio = successDecider.calculateRatio( currentUntampered, currentTampered );
                double d = Math.round( calculateRatio * 100.0 ) / 100.0;

                String dName = attackModel.getDoSAttack() != null ? attackModel.getDoSAttack().getName() : "???";
                String msg = String.format( "First execution of %s was successful (ratio: %s).", dName, d );
                logger.info( msg );
                STATE_CONTEXT.setCurrentUntampered( currentUntampered );
                setSuccessfulState( STATE_CONTEXT );
            }
            else
            {
                untampered = null;

                // create the next attack
                AttackModel nextAttack = STATE_CONTEXT.createNextAttack();
                boolean hasFurtherAttack = nextAttack != null;
                STATE_CONTEXT.setHasFurtherAttack( hasFurtherAttack );

                if ( hasFurtherAttack )
                {
                    if ( nextAttack.getRequestType() == UNTAMPERED )
                    {
                        STATE_CONTEXT.setCurrentAttack( nextAttack );
                        STATE_CONTEXT.setDoSState( new UntamperedState() );
                    }
                    else
                    {
                        STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createVerifyUntampered( false ) );
                    }
                }
                else
                {
                    STATE_CONTEXT.setDoSState( new FinishState() );
                }
            }
        }

    }

    @Override
    public void updateTestProbes( Metric metric )
    {
        // we are not interested in testprobes in this state
    }

}
