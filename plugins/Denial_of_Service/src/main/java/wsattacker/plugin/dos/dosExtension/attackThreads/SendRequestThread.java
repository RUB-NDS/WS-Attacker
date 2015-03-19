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
import java.util.EmptyStackException;

import org.apache.commons.lang3.StringUtils;

import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.plugin.dos.dosExtension.attackRunnables.LogRequestRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberNetworktestProbesRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberProbesRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberRequestsRunnable;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;
import wsattacker.plugin.dos.dosExtension.requestSender.Http4RequestSenderImpl;
import wsattacker.plugin.dos.dosExtension.requestSender.RequestSender;
import wsattacker.plugin.dos.dosExtension.requestSender.RequestSenderImpl;

/**
 * Send request to target depending on requestType various data regarding request gets logged
 * 
 * @author af
 */
public class SendRequestThread
    extends Thread
{
    // Refernz auf Model -> hier syncronisieren!!
    private final AttackModel model;

    private final int threadNumber;

    private final String requestType;

    private long timeStart; // ms

    private long timeEnd; // ms

    private long duration; // ns

    private boolean faultFlag = false;

    private boolean errorFlag = false;

    private String responseString = "";

    private static final Boolean useNewMeasure = Boolean.getBoolean( "useNewMeasure" );

    public SendRequestThread( AttackModel model, int threadNumber, String requestType )
    {

        this.model = model;
        this.threadNumber = threadNumber;
        this.requestType = requestType;

        // run Thread
        start();

        // TODO [CHAL 2013-12-31] you shouldn't start a Thread in the
        // constructor!!!
    }

    // new Request is send ONCE and logged!
    @Override
    public void run()
    {

        // do actual sending depending on requestType
        RequestSender requestSender;
        if ( !useNewMeasure )
        {
            requestSender = new RequestSenderImpl( model );
        }
        else
        {
            requestSender = new Http4RequestSenderImpl( model );
        }

        // Start time
        timeStart = System.currentTimeMillis();

        // TODO [CHAL 2013-12-31] we have to use enumeration here
        // TODO [CHAL 2013-12-31] where is the networkTest???
        if ( this.requestType.equals( "tampered" ) )
        {
            responseString = requestSender.sendTamperedRequest();
        }
        else if ( this.requestType.equals( "untampered" ) )
        {
            responseString = requestSender.sendUntamperedRequest();
        }
        else if ( this.requestType.equals( "testProbe" ) )
        {
            responseString = requestSender.sendTestProbeRequest();
        }
        else
        {
            throw new EmptyStackException();
        }

        // Stop time
        timeEnd = System.currentTimeMillis();

        // calculate the duration, the RequestSender knows its timing
        duration = requestSender.getReceiveTime() - requestSender.getSendTime();

        // Check for empty Response or SOAP-Fault
        // - SOAP-Fault check by finding end of closing Tag "Fault>"
        if ( StringUtils.isEmpty( responseString ) )
        {
            errorFlag = true;
        }
        else if ( responseString.contains( "Fault>" ) )
        {
            faultFlag = true;
        }

        // Log time -> done in context of EDT
        LogRequestRunnable log =
            new LogRequestRunnable( this.model, this.requestType, timeStart, timeEnd, duration, this.threadNumber,
                                    faultFlag, errorFlag, responseString );
        EventQueue.invokeLater( log );

        // Update GUI + Counter
        // - since called via runnable, Method will be executed in EDT -> no
        // Problems with Syncronization!
        if ( this.requestType.equals( "tampered" ) || this.requestType.equals( "untampered" ) )
        {
            UpdateNumberRequestsRunnable update = new UpdateNumberRequestsRunnable( model, requestType );
            EventQueue.invokeLater( update );
        }
        else if ( this.requestType.equals( "testProbe" ) )
        {
            UpdateNumberProbesRunnable update = new UpdateNumberProbesRunnable( model );
            EventQueue.invokeLater( update );
        }
        else if ( this.requestType.equals( "networkTest" ) )
        {
            UpdateNumberNetworktestProbesRunnable update = new UpdateNumberNetworktestProbesRunnable( model );
            EventQueue.invokeLater( update );
        }

        // Log completion
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Trace, getName(), "Done Sending " + this.requestType
                                          + "-Request in " + duration + " ns" ) );
    }
}
