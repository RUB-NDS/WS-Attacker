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
package wsattacker.plugin.dos.dosExtension.clock;

import java.awt.EventQueue;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * After Attack Button is pressed, this Thread is started and RUNS IN LOOP!.. It continuously takes an
 * UpdateClock-Object and puts it in the GUI-EventQueue.. Was passiert wenn ich ein Objekt der GUI-EventQueue übergebe??
 * wird automatisch run() ausgeführt?? -> JA, siehe Doko -> public static void invokeLater(Runnable runnable) Causes
 * runnable to have its run method called in the dispatch thread of the EventQueue. This will happen after all pending
 * events are processed. Has to be this way -> pages S.216 ff. -> Thread NEVER updates GUI (or model???) itself!!
 * 
 * @author af
 */
public class TickerThread
    extends Thread
{ // implements Oberservable Subject
    private final static int UPDATE_INTERVAL = 1000; // ms

    private UpdateClockRunnable update;

    private AttackModel model;

    public TickerThread( AttackModel model )
    {
        // hier neues ThreadUpdate-Objekt bauen!
        // macht nix anderes als einmal Clock update auszuführen und dann
        // fertig..
        this.model = model;
        update = new UpdateClockRunnable( model );

        // Start Thread
        start();
    }

    // Always executed when start() is called
    // HERE: Start is called in Konstruktor!
    // HERE: runs in endless loop forever!!!
    @Override
    public void run()
    {
        try
        {
            while ( !isInterrupted() )
            {
                // Warum kann ich nicht hier direkt ModelMethode aufrufen und so
                // GUI-Update provozieren?
                // -> einfach BadPractice?! kann zu Problemen führen S. 216
                // -> Gibt daher extra diese EventQueue = EDT, dort werden alle
                // GUI-Änderungswünsche sequentiell abgearbeitet!!
                // -> NEIN: model.updateClock(model.getClock().update());
                EventQueue.invokeLater( update );
                Thread.sleep( UPDATE_INTERVAL );
            }
        }
        catch ( InterruptedException e )
        {
        }
    }
}
