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
package wsattacker.plugin.dos.dosExtension.mvc.view;

import javax.swing.JLabel;

import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * JLabel, das den Status ausgibt!
 * 
 * @author af
 */
@SuppressWarnings( "serial" )
public class StatusView
    extends JLabel
    implements AttackListener
{

    public StatusView()
    {
        this( null );
    }

    // Konstruktor mit Status
    public StatusView( AttackModel model )
    {
    }

    /**
     * implementiert Attack Listener, daher ist diese Methode vorhanden... wird immer automatisch aufgerufen, wenn model
     * sich geändert hat!
     */
    @Override
    public void valueChanged( AttackModel model )
    {
        // Set Text of Label!
        String textHead =
            "" + "<html>" + "<body style=\"color:#8F8F8F\">" + "<i style=\"color:#C70050\">"
                + model.getCurrentAttackState() + "</i><br />" + "<br />" + "Time Attack running: "
                + model.getAttackTime() + " seconds<br />" + "";
        String textNetwork;
        if ( model.isNetworkTestEnabled() )
        {
            if ( model.isNetworkTestFinished() )
            {
                textNetwork =
                    "" + "Networktest: " + model.getNetworkTestResult() + " - " + model.getNetworkTestResultString()
                        + "<br /><br />";
            }
            else
            {
                textNetwork = "" + "Networktest: no results yet" + "<br /><br />";
            }
        }
        else
        {
            textNetwork = "" + "Networktest disabled" + "<br /><br />";
        }

        String networkTestStatus;
        if ( model.isNetworkTestEnabled() )
        {
            networkTestStatus =
                "<tr>" + "<td>Status Network Stability Test</td>" + "<td>"
                    + model.getCounterRequestsSend( "networkTest" ) + " / " + ( model.getNetworkTestNumberRequests() )
                    + "</td>" + "</tr>" + "<tr>" + "<td colspan=\"2\">" + "<hr>" + "</td>" + "</tr>";
        }
        else
        {
            networkTestStatus = "";
        }

        String textTable =
            "" + "<table>" + networkTestStatus + "<tr>" + "<td>Number Untampered Threads</td>" + "<td>"
                + model.getCounterThreadsUntampered() + " / " + model.getNumberThreads() + "</td>" + "</tr>" + "<tr>"
                + "<td>Number Untampered Requests</td>" + "<td>" + model.getCounterRequestsSendUntampered() + " / "
                + ( model.getNumberRequestsPerThread() * model.getNumberThreads() ) + "</td>" + "</tr>" + "<tr>"
                + "<td colspan=\"2\">" + "<hr>" + "</td>" + "</tr>" + "<tr>" + "<td>Number Tampered Threads</td>"
                + "<td>" + model.getCounterThreadsTampered() + " / " + model.getNumberThreads() + "</td>" + "</tr>"
                + "<tr>" + "<td>Number Tampered Requests</td>" + "<td>" + model.getCounterRequestsSendTampered()
                + " / " + ( model.getNumberRequestsPerThread() * model.getNumberThreads() ) + "</td>" + "</tr>"
                + "<tr>" + "<td colspan=\"2\">" + "<hr style=\"height:1px;\">" + "</td>" + "</tr>" + "<tr>"
                + "<td>Test Probes Send</td>" + "<td>" + model.getCounterProbesSend() + "</td>" + "</tr>" + "</table>"
                + "<br />" + "</body>" + "</html>";
        setText( textHead + textNetwork + textTable );
    }
}
