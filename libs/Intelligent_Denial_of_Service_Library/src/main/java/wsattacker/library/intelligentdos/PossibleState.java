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
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.helper.CommonParamItem;

/**
 * @author Christian Altmeier
 */
public class PossibleState
    extends AbstractDoSState
{
    private static enum NPS
    {
        NONE, SERVICE_DOWN, REVALIDATE, PARAM, POSSIBLE
    }

    private static final int RESENDS = 1;

    private final CommonParamItem minParamItem = new CommonParamItem( 1, 1, 1000 );

    private NPS verify = NPS.NONE;

    private int count = 0;

    private AttackModel reference = null;

    @Override
    public String getName()
    {
        return "possible state";
    }

    @Override
    public void update( IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {
        switch ( verify )
        {
            case NONE:
                reference = attackModel;

                if ( attackModel.isAllSOAPFault() )
                {
                    AttackModel min = createMinimalUntampered( STATE_CONTEXT );
                    setAttack( STATE_CONTEXT, min );
                }
                else
                {
                    // create untampered with recovery
                    createUTR( STATE_CONTEXT );
                }

                count++;

                verify = NPS.SERVICE_DOWN;

                break;
            case SERVICE_DOWN:
                verifyServiceDown( STATE_CONTEXT, attackModel );

                break;
            case REVALIDATE:
                revalidateAttackFails( STATE_CONTEXT, attackModel );

                break;
            case PARAM:
                // minimal param 1 request / 1 thread / 1 second

                // only one request by one thread is send, so either all fail or
                // none fail
                if ( attackModel.isAllFail() )
                {
                    // all requests had been unsuccessful -> check if this DoS
                    // Attack is possible at all
                    AttackModel minimalAttack = createMinimalDoSAttack( STATE_CONTEXT );
                    switchTo( NPS.POSSIBLE, STATE_CONTEXT, minimalAttack );
                }
                else
                {
                    ThresholdState thresholdState =
                        new ThresholdState( attackModel.getParamItem(), reference.getParamItem() );
                    STATE_CONTEXT.setDoSState( thresholdState );
                    STATE_CONTEXT.update( attackModel );
                }

                break;
            case POSSIBLE:
                if ( attackModel.isAllFail() )
                {
                    STATE_CONTEXT.addNotPossible( attackModel.getDoSAttack() );

                    // as this attack is not possible, the next request will be an
                    // UNTAMPERED request
                    continueAttacks( STATE_CONTEXT );
                }
                else if ( !attackModel.wasAttackExecutionSuccessful() )
                {
                    if ( count > RESENDS )
                    {
                        logger.warn( "Further investigation is not possible! " + attackModel.getErrorCount()
                            + " requests has not been send successfully. Abort execution." );
                        switchToFinishState( STATE_CONTEXT );
                    }
                    else
                    {
                        AttackModel minimalAttack = createMinimalDoSAttack( STATE_CONTEXT );
                        setAttack( STATE_CONTEXT, minimalAttack );

                        count++;
                    }
                }
                else
                {
                    ThresholdState thresholdState = new ThresholdState( attackModel, reference );
                    STATE_CONTEXT.setDoSState( thresholdState );
                    STATE_CONTEXT.update( attackModel );
                }

                break;

            default:
                break;
        }

    }

    private void verifyServiceDown( IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {
        // verify service is not down
        if ( attackModel.isAllFail() )
        {
            if ( attackModel.isAllSOAPFault() )
            {
                logger.warn( "The SOAP request seems to be malformed! No request was send successfully. Abort execution." );
            }
            else
            {
                logger.warn( "Service seems to be down! No request was send successfully. Abort execution." );
            }

            switchToFinishState( STATE_CONTEXT );
        }
        else if ( !attackModel.wasAttackExecutionSuccessful() )
        {
            if ( count > 1 )
            {
                logger.warn( "Further investigation is not possible! " + attackModel.getErrorCount()
                    + " requests has not been send successfully. Abort execution." );
                switchToFinishState( STATE_CONTEXT );
            }
            else
            {
                // network seems unstable
                // create untampered with recovery
                createUTR( STATE_CONTEXT );
                count++;
            }
        }
        else
        {
            count = 0;
            // create a tampered
            AttackModel tampered = STATE_CONTEXT.createNewTampered( true );
            setAttack( STATE_CONTEXT, tampered );

            verify = NPS.REVALIDATE;
        }
    }

    private void revalidateAttackFails( IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {
        if ( attackModel.isAllFail() )
        {
            // create tampered with minimal param (requests, threads, millies)
            AttackModel minimalAttack = createTRWithParam( STATE_CONTEXT, minParamItem );
            count++;
            switchTo( NPS.PARAM, STATE_CONTEXT, minimalAttack );
        }
        else if ( attackModel.wasAttackExecutionSuccessful() )
        {
            if ( count >= RESENDS )
            {
                // attack was executed successfully, return to TamperedState
                STATE_CONTEXT.setDoSState( new TamperedState() );
                STATE_CONTEXT.update( attackModel );
            }
            else
            {
                // create a tampered
                AttackModel tampered = STATE_CONTEXT.createNewTampered( true );
                setAttack( STATE_CONTEXT, tampered );

                count++;
            }
        }
        else
        {
            // create tampered with minimal param (requests, threads,
            // millies)
            AttackModel minimalAttack = createTRWithParam( STATE_CONTEXT, minParamItem );
            count++;
            switchTo( NPS.PARAM, STATE_CONTEXT, minimalAttack );
        }
    }

    private void switchTo( NPS verify, IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {
        count = 0;

        setAttack( STATE_CONTEXT, attackModel );

        this.verify = verify;
    }

    private AttackModel createMinimalDoSAttack( IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        DoSAttack minimal = reference.getDoSAttack().minimal();
        AttackModel tampered = STATE_CONTEXT.createNewTampered( minimal );

        return tampered;
    }

    private AttackModel createMinimalUntampered( IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        DoSAttack minimal = reference.getDoSAttack().minimal();
        AttackModel untampered = STATE_CONTEXT.createNewUntampered( minimal );

        return untampered;
    }

    @Override
    public void updateTestProbes( Metric metric )
    {
        // not interested
    }

}
