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

import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberProbesRunnable;


import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * Send Probe Requests in parallel while the attack is running! IMPORTANT: -
 * This Thread runs forever!!! (Just as the attack itself runs forever) - Only
 * way to stop it is to call ABORT or FINALIZE
 *
 * What it does: - Send untampered Probe and Measure response time - wait
 * secondsBetweenProbes ms and send next Probe - Add response time to discrete
 * Interval data structure(measured how??) - Log type of response ??
 *
 * @author af
 *
 */
public class RepeatTestprobeRequestThread extends Thread {  // implements Oberservable Subject

    private AttackModel model; 

    public RepeatTestprobeRequestThread(AttackModel model) {
	this.model = model;
    }

    // run as long as attack is not finalized
    public void run() {
	while (!isInterrupted()) {
	    try {
		// Send Request via new Thread
		new SendRequestThread(this.model, 0, "testProbe");

		// Wait X seconds as defined in model
		Thread.sleep(this.model.getSecondsBetweenProbes());
	    } catch (InterruptedException e) {
		//System.out.println("interrupt in Sleep1");
		Thread.currentThread().interrupt();
		return;
	    }
	}
    }
}
