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

import com.google.common.collect.Lists;
import java.util.List;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestObject;
import wsattacker.plugin.intelligentdos.listener.RecentTestProbeListener;
import wsattacker.plugin.intelligentdos.requestSender.Http4RequestSenderImpl;

public class TestProbeThread
    extends Thread
{

    private static final int MILLIES_BETWEEN_PROBES = 1000;

    private final RequestObject requestObject;

    private final List<RecentTestProbeListener> listeners = Lists.newArrayList();

    public TestProbeThread( RequestObject requestObject )
    {
        this.requestObject = requestObject;
    }

    @Override
    public void run()
    {
        while ( !interrupted() )
        {

            try
            {
                Http4RequestSenderImpl impl = new Http4RequestSenderImpl();

                String sendRequestHttpClient = impl.sendRequestHttpClient( requestObject );
                long duration = impl.getDuration();

                Metric metric = new Metric();
                metric.setDuration( duration );
                metric.setContent( sendRequestHttpClient );

                notifyListener( metric );

                // Wait X milliseconds
                Thread.sleep( MILLIES_BETWEEN_PROBES );
            }
            catch ( InterruptedException e )
            {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    public void addListener( RecentTestProbeListener listener )
    {
        listeners.add( listener );
    }

    public void removeListener( RecentTestProbeListener listener )
    {
        listeners.remove( listener );
    }

    private void notifyListener( Metric metric )
    {
        for ( RecentTestProbeListener listener : listeners )
        {
            listener.recentTestProbe( metric );
        }

    }

}
