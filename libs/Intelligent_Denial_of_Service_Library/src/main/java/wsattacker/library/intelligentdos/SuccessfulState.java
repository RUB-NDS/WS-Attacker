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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import java.util.List;
import org.apache.log4j.Logger;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import static wsattacker.library.intelligentdos.common.RequestType.UNTAMPERED;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.success.Efficiency;
import wsattacker.library.intelligentdos.success.SuccessDecider;

/**
 * @author Christian Altmeier
 */
public class SuccessfulState
    implements DoSState
{
    private final Logger logger = Logger.getLogger( getClass() );

    private AttackModel untampered;

    private final List<Metric> list = Lists.newArrayList();

    @Override
    public String getName()
    {
        return "successful state";
    }

    /*
     * (non-Javadoc)
     * @see state.Statelike#writeName(state.StateContext, java.lang.String)
     */
    @Override
    public void update( final IntelligentDoSLibraryImpl STATE_CONTEXT, final AttackModel attackModel )
    {

        SuccessDecider successDecider = STATE_CONTEXT.getSuccessDecider();

        if ( untampered == null )
        {
            untampered = attackModel;

            // check for
            double ratio =
                successDecider.calculateRatio( STATE_CONTEXT.getCurrentUntampered(), attackModel.getDurationArray() );
            if ( SuspiciousState.isSuspicious( ratio ) )
            {
                // create the same attack (tampered) again
                STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createNewUntampered( false ) );
                STATE_CONTEXT.setHasFurtherAttack( true );
                STATE_CONTEXT.setDoSState( new SuspiciousState() );
            }
            else
            {
                // create the same attack (tampered) again
                STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createNewTampered( false ) );
                STATE_CONTEXT.setHasFurtherAttack( true );
            }
        }
        else
        {
            Long[] currentUntampered = untampered.getDurationArray();
            Long[] currentTampered = attackModel.getDurationArray();

            boolean successful = successDecider.wasSuccessful( currentUntampered, currentTampered );
            Efficiency efficency = successDecider.getEfficency( currentUntampered, currentTampered );
            double ratio = successDecider.calculateRatio( currentUntampered, currentTampered );
            double ratioFormated = Math.round( ratio * 100.0 ) / 100.0;

            if ( successful )
            {
                String dName = attackModel.getDoSAttack() != null ? attackModel.getDoSAttack().getName() : "???";
                String msg = String.format( "%s was successful (ratio: %s)", dName, ratioFormated );
                logger.info( msg );

                // create SuccessfulAttack object
                SuccessfulAttack successfulAttack = createSuccessfulAttack( attackModel );
                successfulAttack.setEfficiency( efficency );
                successfulAttack.setRatio( ratio );

                // store the attack to the service
                STATE_CONTEXT.addSuccessful( ( successfulAttack ) );

                AttackModel createNextAttack = STATE_CONTEXT.createNextAttack( true );
                STATE_CONTEXT.setCurrentAttack( createNextAttack );
                STATE_CONTEXT.setHasFurtherAttack( createNextAttack != null );

                if ( createNextAttack != null )
                {
                    if ( createNextAttack.getRequestType() == UNTAMPERED )
                    {
                        STATE_CONTEXT.setDoSState( new UntamperedState() );
                    }
                    else
                    {
                        STATE_CONTEXT.setDoSState( new TamperedState() );
                    }
                }
                else
                {
                    STATE_CONTEXT.setDoSState( new FinishState() );
                }
            }
            else
            {
                String dName = attackModel.getDoSAttack() != null ? attackModel.getDoSAttack().getName() : "???";
                String msg = String.format( "%s was not successful (ratio: %s).", dName, ratioFormated );
                logger.info( msg );

                // create a new untampered attack
                STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createNewUntampered( true ) );
                STATE_CONTEXT.setHasFurtherAttack( true );

                STATE_CONTEXT.setDoSState( new UntamperedState() );
            }
        }
    }

    private SuccessfulAttack createSuccessfulAttack( final AttackModel attackModel )
    {
        SuccessfulAttack successfulAttack =
            new SuccessfulAttack( attackModel.getDoSAttack(), attackModel.getParamItem() );
        successfulAttack.setPosition( attackModel.getPosition() );
        successfulAttack.setPayloadPosition( attackModel.getPayloadPosition() );
        if ( attackModel.getPosition() != null && attackModel.getPayloadPosition() != null )
        {
            successfulAttack.setXmlWithPlaceholder( attackModel.getPosition().createPlaceholder( attackModel.getPayloadPosition() ) );
        }
        successfulAttack.setUntamperedContent( untampered.getRequestContent() );
        successfulAttack.setUntamperedMetrics( untampered.getMetrics() );
        successfulAttack.setTamperedContent( attackModel.getRequestContent() );
        successfulAttack.setTamperedMetrics( attackModel.getMetrics() );
        successfulAttack.setTestProbes( ImmutableList.copyOf( list ) );
        return successfulAttack;
    }

    @Override
    public void updateTestProbes( Metric metric )
    {
        synchronized ( list )
        {
            list.add( metric );
        }
    }

}