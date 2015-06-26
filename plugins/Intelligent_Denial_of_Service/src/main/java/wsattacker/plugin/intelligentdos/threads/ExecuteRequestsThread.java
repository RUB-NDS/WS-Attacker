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
package wsattacker.plugin.intelligentdos.threads;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.RequestObject;

/**
 * @author Christian Altmeier
 */
public class ExecuteRequestsThread
    extends Thread
{

    private static final Logger logger = Logger.getLogger( ExecuteRequestsThread.class );

    private final AttackModel attackModel;

    private final RequestObject requestObject;

    private final int numberOfRequests;

    private final int secondsBetweenRequests;

    public ExecuteRequestsThread( AttackModel attackModel, RequestObject requestObject, int numberOfRequests,
                                  int secondsBetweenRequests )
    {
        this.attackModel = attackModel;
        this.requestObject = requestObject;
        this.numberOfRequests = numberOfRequests;
        this.secondsBetweenRequests = secondsBetweenRequests;
    }

    @Override
    public void run()
    {
        List<Thread> threadList = new ArrayList<Thread>();
        try
        {
            for ( int requestNumber = 0; requestNumber < numberOfRequests; requestNumber++ )
            {

                Thread sendRequestThread = new SendRequestThread( attackModel, requestObject );
                sendRequestThread.start();
                threadList.add( sendRequestThread );

                try
                {
                    // Wait for time period as defined in model!
                    Thread.sleep( secondsBetweenRequests );
                }
                catch ( InterruptedException e )
                {

                }
            }

            // bring the threads together again
            for ( Thread thread : threadList )
            {
                thread.join();
            }
        }
        catch ( InterruptedException e )
        {
            logger.error( e.toString(), e );
        }
    }
}
