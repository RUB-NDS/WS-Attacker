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

import java.awt.EventQueue;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestObject;
import wsattacker.plugin.intelligentdos.requestSender.Http4RequestSenderImpl;

/**
 * @author Christian Altmeier
 */
public class SendRequestThread
    extends Thread
{

    private final AttackModel attackModel;

    private final RequestObject requestObject;

    public SendRequestThread( AttackModel attackModel, RequestObject requestObject )
    {
        this.attackModel = attackModel;
        this.requestObject = requestObject;
    }

    @Override
    public void run()
    {
        Http4RequestSenderImpl impl = new Http4RequestSenderImpl();

        String sendRequestHttpClient = impl.sendRequestHttpClient( requestObject );
        long duration = impl.getDuration();

        Metric metric = new Metric();
        metric.setDuration( duration );
        metric.setContent( sendRequestHttpClient );

        attackModel.addMetric( metric );

        // TODO [chal 2014-07-03] find a better solution
        EventQueue.invokeLater( new Runnable()
        {
            @Override
            public void run()
            {
                attackModel.increase();
            }
        } );
    }
}
