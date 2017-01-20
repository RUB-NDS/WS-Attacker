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
package wsattacker.plugin.dos.dosExtension.attackThreads;

import java.awt.EventQueue;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.plugin.dos.dosExtension.attackRunnables.AutoFinalizeAttackRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.NetworktestResultRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateAttackStateRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberThreadsRunnable;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * Perform Attack as described in Activitydiagram. This includes: - Network stability test ? - N x M untampered requests
 * - Wait X seconds - N x M tampered requests How long does it run? - As long as one of these conditions is meet: - end
 * is reached = - - close is pressed = just kill thread all together!
 * 
 * @author af
 */
public class PerformAttackThread
    extends Thread
{

    private static final int MIN = 5;

    private static final int MAX = 50;

    private final AttackModel model; // refernce on attackModel

    private int delay;

    public boolean sendUntampered = true;

    public PerformAttackThread( AttackModel model )
    {
        this.model = model;
    }

    public boolean isSendUntampered()
    {
        return sendUntampered;
    }

    public void setSendUntampered( boolean sendUntampered )
    {
        this.sendUntampered = sendUntampered;
    }

    // Always executed when start() is called
    @Override
    public void run()
    {

        // Network stability test
        // - only if enabled!
        if ( this.model.isNetworkTestEnabled() )
        {
            try
            {
                networkTest();
            }
            catch ( InterruptedException e )
            {
                return; // cheap way to end if interrupted!
            }
        }

        // Start sending Untampered probes in Parallel
        this.model.setSendProbeRequestsThread( new RepeatTestprobeRequestThread( this.model ) );
        this.model.getSendProbeRequestsThread().start();

        try
        {
            if ( sendUntampered )
            {
                // N x M untampered requests
                untamperedRequests();

                // Server Recovery Time!
                // Wait X seconds, as passed by parameter
                serverRecovery();
            }

            // N x M tampered requests
            tamperedRequests();

            // Is AutoFinalize switched on or off?
            if ( model.isAutoFinalizeSwitch() )
            {
                autoFinalize();
            }
            else
            {
                manualFinalize();
            }

        }
        catch ( InterruptedException e )
        {
            this.interrupt();
            return; // cheap way to end if interrupted!
        }

    }

    private void networkTest()
        throws InterruptedException
    {
        EventQueue.invokeLater( new UpdateAttackStateRunnable( this.model, 1 ) );
        for ( int i = 0; i < this.model.getNetworkTestNumberRequests(); i++ )
        {
            try
            {
                // Send Request via new Thread
                new SendRequestThread( this.model, 0, "networkTest" );

                // Wait X seconds as defined in model
                Thread.sleep( this.model.getNetworkTestRequestInterval() );
            }
            catch ( InterruptedException e )
            {
                // TODO [CHAL 2013-12-31] Remove System.out!
                Thread.currentThread().interrupt();
                throw e;
            }
        }

        try
        {
            waitForNetworkTestRequests();
        }
        catch ( InterruptedException e )
        {
            this.interrupt();
            throw e;
        }

        // Write Coefficient_of_variation to Model and update GUI!
        // - see http://en.wikipedia.org/wiki/Coefficient_of_variation
        // - Update GUI...
        EventQueue.invokeLater( new NetworktestResultRunnable( this.model ) );
    }

    private void untamperedRequests()
        throws InterruptedException
    {
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(),
                                                       "Start sending untampered requests to target" ) );
        EventQueue.invokeLater( new UpdateAttackStateRunnable( this.model, 2 ) );
        // TODO: Make nicer - even though it causes no problem
        model.setTsUntamperedStart( System.currentTimeMillis() );

        for ( int i = 0; i < this.model.getNumberThreads(); i++ )
        {
            // New Repeat-Request N-Times Object
            new RepeatAttackRequestThread( model, i, "untampered" );

            // Update GUI with NumberRequestsSend
            EventQueue.invokeLater( new UpdateNumberThreadsRunnable( this.model, "untampered" ) );

            // Delay start of next thread for a couple of ms to prevent
            // sending at same time
            delay = 5; // min + (int)(Math.random() * ((max - min) + 1));
            Thread.sleep( delay );
        }

        // TODO [CHAL 2014-02-04]: thread.join instead of
        // waitForUntamperedRequests
        waitForUntamperedRequests();
    }

    private void serverRecovery()
        throws InterruptedException
    {
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(), "Server recovery time" ) );
        EventQueue.invokeLater( new UpdateAttackStateRunnable( this.model, 3 ) );
        Thread.sleep( this.model.getSecondsServerLoadRecovery() );
    }

    private void tamperedRequests()
        throws InterruptedException
    {
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(),
                                                       "Start sending tampered requests to target" ) );
        EventQueue.invokeLater( new UpdateAttackStateRunnable( this.model, 4 ) );
        // Todo: Make nicer - even though it causes no problem
        model.setTsTamperedStart( System.currentTimeMillis() );
        for ( int i = 0; i < this.model.getNumberThreads(); i++ )
        {
            // New Repeat-Request N-Times Object
            new RepeatAttackRequestThread( model, i, "tampered" );

            // Update GUI With Number Attack Threads started
            EventQueue.invokeLater( new UpdateNumberThreadsRunnable( this.model, "tampered" ) );

            // Delay start of next thread for a couple of ms to prevent
            // sending at same time
            delay = MIN + (int) ( Math.random() * ( ( MAX - MIN ) + 1 ) );
            Thread.sleep( delay );
        }

        waitForTamperedRequests();
    }

    private void waitForNetworkTestRequests()
        throws InterruptedException
    {
        // Wait until all NetworkStabilityTest-Requests are done!!
        // Via Loop that checks for "threadAbove" still running?
        String requestType = "networkTest";
        int numberRequests = this.model.getNetworkTestNumberRequests();

        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(), "Waiting for all " + requestType
                                          + " requests to return" ) );
        EventQueue.invokeLater( new UpdateAttackStateRunnable( this.model, 2 ) );
        while ( this.model.getCounterRequestsSend( requestType ) != numberRequests && !isInterrupted() )
        {
            Thread.sleep( 1000 );
        }
    }

    private void waitForUntamperedRequests()
        throws InterruptedException
    {
        // Wait until all Untampered Requests are done!!
        // Via Loop that checks for "threadAbove" still running?
        String requestType = "untampered";
        int numberRequests = this.model.getRequestsTotal();

        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(), "Waiting for all " + requestType
                                          + " requests to return" ) );
        EventQueue.invokeLater( new UpdateAttackStateRunnable( this.model, 2 ) );
        while ( this.model.getCounterRequestsSend( requestType ) != numberRequests && !isInterrupted() )
        {
            Thread.sleep( 1000 );
        }
    }

    private void waitForTamperedRequests()
        throws InterruptedException
    {
        // Wait until all processes above are done!!
        // Via Loop that checks for "threadAbove" still running?
        String requestType = "tampered";
        int numberRequests = this.model.getRequestsTotal();

        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(), "Waiting for all " + requestType
                                          + " requests to return" ) );
        // TODO [CHAL 2013-12-31] why don't we need UpdateAttackStateRunnable
        // here?
        while ( this.model.getCounterRequestsSend( requestType ) != numberRequests && !isInterrupted() )
        {
            Thread.sleep( 1000 );
        }
    }

    private void autoFinalize()
        throws InterruptedException
    {
        EventQueue.invokeLater( new UpdateAttackStateRunnable( this.model, 9 ) );
        // Let Attack run for defined amount of time

        Thread.sleep( model.getAutoFinalizeSeconds() );

        // finish attack by finilazing it!
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(), "Attack is done" ) );
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(), "Auto Finalization just started" ) );
        EventQueue.invokeLater( new AutoFinalizeAttackRunnable( this.model ) );
    }

    private void manualFinalize()
    {
        // DONE, Finalize Button can now be enabled
        // - again via custom runnable that is invoked via invokeLater
        // - custom runnable calls model.updateStatus(X), that in return
        // updates GUI!!
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, getName(), "Attack is ready to be finalized" ) );
        EventQueue.invokeLater( new UpdateAttackStateRunnable( this.model, 5 ) );
    }
}
