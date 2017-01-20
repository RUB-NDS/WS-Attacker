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

import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * Send tampered/untampered request N times sequentially to target Thread waits X seconds between every request as
 * defined in Model!
 * 
 * @author af
 */
public class RepeatAttackRequestThread
    extends Thread
{ // implements
  // Oberservable Subject

    // Refernz auf Model -> hier syncronisieren!!
    private final AttackModel model;

    private final int threadNumber;

    private final String requestType;

    /**
     * Constructor
     * 
     * @param model
     * @param threadNumber
     * @param requestType -> send tampered or untampered request
     */
    public RepeatAttackRequestThread( AttackModel model, int threadNumber, String requestType )
    {

        this.model = model;
        this.threadNumber = threadNumber;
        this.requestType = requestType;

        // run Thread
        start();

        // TODO [CHAL 2013-12-31] you shouldn't start a Thread in the
        // constructor!!!
    }

    // a new Send-Request-Object is send N times sequentially
    @Override
    public void run()
    {
        for ( int i = 0; i < model.getNumberRequestsPerThread(); i++ )
        {
            // Check if attack is aborted!
            if ( !model.isAttackAborted() )
            {

                try
                {
                    // Open new Thread that sends new Request!
                    new SendRequestThread( this.model, this.threadNumber, this.requestType );

                    // Wait for time period as defined in model!
                    Thread.sleep( model.getSecondsBetweenRequests() );
                }
                catch ( InterruptedException e )
                {
                    // Fall MainThread interrupt in SleepPhase kommt wird diese
                    // Exception gelöst
                    // ABER danach exception Flag wieder auf Null gesetzt, daher
                    // hier nochmal neu interupten!
                    // Siehe:
                    // http://openbook.galileodesign.de/javainsel5/javainsel09_003.htm#t2t35
                    this.interrupt();
                }
            }
            else
            {
                return;
            }
        }
        // Todo: ugly - find better solution
        model.setTsTamperedLastSend( System.currentTimeMillis() );
    }
}
