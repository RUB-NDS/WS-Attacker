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
package wsattacker.plugin.intelligentdos.worker;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.apache.log4j.Logger;

import wsattacker.library.intelligentdos.IntelligentDoSLibrary;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestObject;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.plugin.intelligentdos.listener.AttackModelChangeListener;
import wsattacker.plugin.intelligentdos.listener.AttackPerformedListener;
import wsattacker.plugin.intelligentdos.listener.RecentTestProbeListener;
import wsattacker.plugin.intelligentdos.model.ResultModel;
import wsattacker.plugin.intelligentdos.threads.ExecuteRequestsThread;
import wsattacker.plugin.intelligentdos.threads.TestProbeThread;

import com.eviware.soapui.impl.wsdl.submit.transports.http.WsdlResponse;
import com.eviware.soapui.support.types.StringToStringsMap;
import com.google.common.collect.Lists;

public class IntelligentDoSWorker
    implements RecentTestProbeListener
{

    private static final int MIN = 5;

    private static final int MAX = 25;

    private final IntelligentDoSLibrary intelligentDoSLibrary;

    private final Logger logger = Logger.getLogger( getClass() );

    private final List<AttackModelChangeListener> changedListeners = Lists.newArrayList();

    private final List<AttackPerformedListener> performedListeners = Lists.newArrayList();

    private boolean abort = false;

    private boolean finished = true;

    private int count = 0;

    private Date start;

    private Date stop;

    private TestProbeThread testProbeThread;

    public IntelligentDoSWorker( IntelligentDoSLibrary intelligentDoSLibrary )
    {
        this.intelligentDoSLibrary = intelligentDoSLibrary;
    }

    public void startAttack( RequestResponsePair original )
    {
        finished = false;
        start = new Date();

        // Header have to be taken from response
        Map<String, String> headerMap = createHttpHeaderMap( original.getWsdlResponse() );

        RequestObject testProbeRO =
            new RequestObject( intelligentDoSLibrary.getTestProbeContent(), original.getWsdlRequest().getEndpoint(),
                               headerMap );
        testProbeThread = new TestProbeThread( testProbeRO );
        testProbeThread.addListener( this );
        testProbeThread.start();

        int i = 5;
        while ( !abort && intelligentDoSLibrary.hasFurtherAttack() )
        {

            if ( count % i == 0 )
            {
                logger.debug( "\tattack " + ( count + 1 ) + " start: " + new java.util.Date() );
            }

            AttackModel attackModel = intelligentDoSLibrary.nextAttack();
            fireModelChanged( attackModel );

            try
            {
                if ( attackModel.getServerRecoveryBeforeSend() != 0 )
                {
                    logger.trace( "Server Recovery: " + attackModel.getServerRecoveryBeforeSend() + "!" );
                    Thread.sleep( attackModel.getServerRecoveryBeforeSend() );
                }

                String content = attackModel.getRequestContent();
                RequestObject requestObject =
                    new RequestObject( content, original.getWsdlRequest().getEndpoint(), headerMap );

                sendAttack( attackModel, requestObject );
            }
            catch ( InterruptedException e )
            {
                logger.error( e.toString(), e );
            }

            if ( count % i == 0 )
            {
                logger.debug( "\tattack " + ( count + 1 ) + " stop: " + new java.util.Date() );
            }
            count++;
            intelligentDoSLibrary.update( attackModel );

            fireAttackPerformed( count - 1, attackModel );
        }

        // stop the sending of the testprobes
        testProbeThread.interrupt();

        stop = new Date();

        finished = true;
    }

    public boolean isFinished()
    {
        return finished;
    }

    public ResultModel getResult()
    {
        ResultModel resultModel = new ResultModel( intelligentDoSLibrary.getSuccessfulAttacks() );
        resultModel.setStartDate( start );
        resultModel.setStopDate( stop );
        resultModel.setNotPossible( intelligentDoSLibrary.getNotPossible() );
        resultModel.setThresholds( intelligentDoSLibrary.getThresholds() );
        resultModel.setMaximumRequestsPerSecond( intelligentDoSLibrary.getMaximumRequestsPerSecond() );
        return resultModel;
    }

    private void sendAttack( final AttackModel attackModel, final RequestObject requestObject )
        throws InterruptedException
    {

        Thread executorThread = new ExecutorThread( attackModel, requestObject );

        // start as a separate thread
        executorThread.start();
        // but wait until the thread has finished
        executorThread.join();
    }

    public int getCount()
    {
        return count;
    }

    private void fireModelChanged( AttackModel attackModel )
    {
        for ( AttackModelChangeListener listener : changedListeners )
        {
            listener.attackModelChanged( attackModel );
        }
    }

    private void fireAttackPerformed( int count, AttackModel attackModel )
    {
        for ( AttackPerformedListener listener : performedListeners )
        {
            listener.attackPerformed( count, attackModel );
        }
    }

    public void addListener( AttackModelChangeListener attackModelChangeListener )
    {
        changedListeners.add( attackModelChangeListener );
    }

    public void removeListener( AttackModelChangeListener attackModelChangeListener )
    {
        changedListeners.remove( attackModelChangeListener );
    }

    public void addListener( AttackPerformedListener attackPerformedListener )
    {
        performedListeners.add( attackPerformedListener );
    }

    public void removeListener( AttackPerformedListener attackPerformedListener )
    {
        performedListeners.remove( attackPerformedListener );
    }

    /*
     * (non-Javadoc)
     * @see wsattacker.plugin.intelligentdos.listener.RecentTestProbeListener#recent
     * (wsattacker.library.intelligentdos.common.Metric)
     */
    @Override
    public void recentTestProbe( Metric metric )
    {
        intelligentDoSLibrary.updateTestProbes( metric );
    }

    public void stopAttack()
    {
        testProbeThread.interrupt();
        abort = true;
        finished = true;
        // TODO [chal 2014-07-15] interrupt all
    }

    private Map<String, String> createHttpHeaderMap( WsdlResponse wsdlResponse )
    {
        Map<String, String> httpHeaderMap = new HashMap<String, String>();
        StringToStringsMap originalHeaders = wsdlResponse.getRequestHeaders();
        for ( Map.Entry<String, List<String>> entry : originalHeaders.entrySet() )
        {
            for ( String value : entry.getValue() )
            {
                httpHeaderMap.put( entry.getKey(), value );
            }
        }

        return httpHeaderMap;
    }

    private static class ExecutorThread
        extends Thread
    {

        private final AttackModel attackModel;

        private final RequestObject requestObject;

        private final int numberOfThreads;

        private final int numberOfRequests;

        private final int secondsBetweenRequests;

        // create random object
        private final Random random = new Random();

        ExecutorThread( AttackModel attackModel, RequestObject requestObject )
        {
            this.attackModel = attackModel;
            this.requestObject = requestObject;

            this.numberOfThreads = attackModel.getNumberOfThreads();
            this.numberOfRequests = attackModel.getNumberOfRequests();
            this.secondsBetweenRequests = attackModel.getMilliesBetweenRequests();
        }

        @Override
        public void run()
        {
            List<Thread> threads = new ArrayList<Thread>();

            try
            {
                // Delay start of next thread for a couple of ms to
                // prevent sending at same time
                int delay = MIN + random.nextInt( ( MAX - MIN ) + 1 );
                for ( int threadNumber = 0; threadNumber < numberOfThreads; threadNumber++ )
                {
                    // New Repeat-Request N-Times Object
                    ExecuteRequestsThread thread =
                        new ExecuteRequestsThread( attackModel, requestObject, numberOfRequests, secondsBetweenRequests );

                    thread.start();
                    threads.add( thread );

                    Thread.sleep( delay );
                }

                // bring the threads together again
                for ( Thread thread : threads )
                {
                    thread.join();
                }
            }
            catch ( InterruptedException e )
            {
                Logger.getLogger( getClass() ).warn( e.getMessage(), e );
            }
        }
    }

}
