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
import wsattacker.library.intelligentdos.common.Threshold;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.helper.CommonParamItem;

/**
 * @author Christian Altmeier
 */
public class ThresholdState
    extends AbstractDoSState
{

    private static final int RESENDS = 1;

    private static final int ITERATIONS = 4;

    private static enum THS
    {
        PARAM, PARAMTHRESHOLD, VALUE, THRESHOLD
    }

    private CommonParamItem minimumParamItem;

    private CommonParamItem maximumParamItem;

    private AttackModel minimumAttack;

    private AttackModel maximumAttack;

    private int count = 0;

    private int iteration = 0;

    private THS ths = THS.PARAM;

    public ThresholdState( CommonParamItem minimumParamItem, CommonParamItem maximumParamItem )
    {
        this.minimumParamItem = minimumParamItem;
        this.maximumParamItem = maximumParamItem;

        ths = THS.PARAM;
    }

    public ThresholdState( AttackModel minimumAttack, AttackModel maximumAttack )
    {
        this.minimumAttack = minimumAttack;
        this.maximumAttack = maximumAttack;

        ths = THS.VALUE;
    }

    @Override
    public String getName()
    {
        return "threshold state";
    }

    private void setMinimumParamItem( CommonParamItem paramItem )
    {
        this.minimumParamItem = paramItem;
    }

    private void setMaximumParamItem( CommonParamItem paramItem )
    {
        this.maximumParamItem = paramItem;
    }

    private void setMinimumAttack( AttackModel attackModel )
    {
        this.minimumAttack = attackModel;
    }

    private void setMaximumAttack( AttackModel attackModel )
    {
        this.maximumAttack = attackModel;
    }

    @Override
    public void update( IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {

        CommonParamItem middle;
        switch ( ths )
        {
            case PARAM:
                middle = createMiddleForParamItem( minimumParamItem, maximumParamItem );
                AttackModel middleParamAttack = createTRWithParam( STATE_CONTEXT, middle );
                count++;
                switchTo( THS.PARAMTHRESHOLD, STATE_CONTEXT, middleParamAttack );

                break;

            case PARAMTHRESHOLD:
                if ( iteration < ITERATIONS )
                {
                    if ( attackModel.isAllFail() )
                    {
                        // should not happen, because the previous test was
                        // successful
                        // not clear
                        if ( count > RESENDS )
                        {
                            logger.warn( "Further investigation is not possible! " + attackModel.getErrorCount()
                                + " requests has not been send successfully. Abort execution." );
                            switchToFinishState( STATE_CONTEXT );
                        }
                        else
                        {
                            middle = attackModel.getParamItem();
                            AttackModel paramMiddleAttack = createTRWithParam( STATE_CONTEXT, middle );
                            setAttack( STATE_CONTEXT, paramMiddleAttack );
                            count++;
                        }

                    }
                    else if ( attackModel.wasAttackExecutionSuccessful() )
                    {
                        setMinimumParamItem( attackModel.getParamItem() );

                        middle = createMiddleForParamItem( minimumParamItem, maximumParamItem );
                        AttackModel paramMiddleAttack = createTRWithParam( STATE_CONTEXT, middle );
                        setAttack( STATE_CONTEXT, paramMiddleAttack );
                        iteration++;
                    }
                    else
                    {
                        setMaximumParamItem( attackModel.getParamItem() );

                        middle = createMiddleForParamItem( minimumParamItem, maximumParamItem );
                        AttackModel paramMiddleAttack = createTRWithParam( STATE_CONTEXT, middle );
                        setAttack( STATE_CONTEXT, paramMiddleAttack );
                        iteration++;
                    }
                }
                else
                {
                    if ( attackModel.isAllFail() )
                    {
                        // fail
                        setMaximumParamItem( attackModel.getParamItem() );
                    }
                    else if ( attackModel.wasAttackExecutionSuccessful() )
                    {
                        // successful
                        setMinimumParamItem( attackModel.getParamItem() );
                    }

                    STATE_CONTEXT.setMaximumRequestsPerSecond( minimumParamItem.getReuqestsPerSecond() );
                    STATE_CONTEXT.setDoSState( new TamperedState() );
                    continueAttacks( STATE_CONTEXT );

                    resetIteration();
                }

                break;

            case VALUE:
                // create a new attack in the middle of minimum and maximum
                AttackModel middleAttack = createMiddle( STATE_CONTEXT );
                switchTo( THS.THRESHOLD, STATE_CONTEXT, middleAttack );

                resetIteration();
                break;
            case THRESHOLD:

                if ( iteration < ITERATIONS )
                {
                    if ( attackModel.isAllFail() )
                    {
                        // fail
                        setMaximumAttack( attackModel );

                        newFindThresholdIteration( STATE_CONTEXT );
                    }
                    else if ( attackModel.wasAttackExecutionSuccessful() )
                    {
                        // successful
                        setMinimumAttack( attackModel );

                        newFindThresholdIteration( STATE_CONTEXT );
                    }
                    else
                    {
                        // not clear
                        if ( count > RESENDS )
                        {
                            logger.warn( "Further investigation is not possible! " + attackModel.getErrorCount()
                                + " requests has not been send successfully. Abort execution." );
                            switchToFinishState( STATE_CONTEXT );
                        }
                        else
                        {
                            createMiddleAttackAndSetToContext( STATE_CONTEXT );
                            count++;
                        }
                    }
                }
                else
                {
                    if ( attackModel.isAllFail() )
                    {
                        // fail
                        setMaximumAttack( attackModel );
                    }
                    else if ( attackModel.wasAttackExecutionSuccessful() )
                    {
                        // successful
                        setMinimumAttack( attackModel );
                    }

                    STATE_CONTEXT.addThreshold( new Threshold( minimumAttack.getDoSAttack(),
                                                               maximumAttack.getDoSAttack() ) );
                    continueAttacks( STATE_CONTEXT );

                    resetIteration();
                }

                break;
            default:
                break;
        }

    }

    @Override
    public void updateTestProbes( Metric metric )
    {
        // not interested
    }

    private void switchTo( THS ths, IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel attackModel )
    {
        count = 0;

        setAttack( STATE_CONTEXT, attackModel );

        this.ths = ths;
    }

    private CommonParamItem createMiddleForParamItem( CommonParamItem min, CommonParamItem max )
    {
        int requests = max.getNumberOfRequests();
        int threads = max.getNumberOfThreads();
        int millies = max.getMilliesBetweenRequests();

        // first we reduce the number of the threads and then increase the
        // number of millies
        if ( min.getNumberOfThreads() != max.getNumberOfThreads() )
        {
            threads = min.getNumberOfThreads() + ( max.getNumberOfThreads() - min.getNumberOfThreads() ) / 2;
        }

        if ( threads <= 0 || min.getNumberOfThreads() == threads )
        {
            int minMBR = min.getMilliesBetweenRequests();
            if ( min.getMilliesBetweenRequests() == max.getMilliesBetweenRequests() )
            {
                minMBR = 1;
            }

            millies =
                Math.min( minMBR, max.getMilliesBetweenRequests() )
                    + Math.abs( max.getMilliesBetweenRequests() - minMBR ) / 2;
        }

        return new CommonParamItem( requests, threads, millies );
    }

    private void newFindThresholdIteration( IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        createMiddleAttackAndSetToContext( STATE_CONTEXT );

        iteration++;
    }

    private void createMiddleAttackAndSetToContext( IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        // create a new attack in the middle of minimum and maximum
        AttackModel middleAttack = createMiddle( STATE_CONTEXT );
        setAttack( STATE_CONTEXT, middleAttack );
    }

    private AttackModel createMiddle( IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        DoSAttack middle = minimumAttack.getDoSAttack().middle( maximumAttack.getDoSAttack() );
        AttackModel tampered = STATE_CONTEXT.createNewTampered( middle );

        // TODO compareTo - because the attacks can be the same

        return tampered;
    }

    private void resetIteration()
    {
        iteration = 0;
    }

}
