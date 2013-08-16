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
 * Perform Attack as described in Activitydiagram. This includes: - Network
 * stability test ? - N x M untampered requests - Wait X seconds - N x M
 * tampered requests
 *
 * How long does it run? - As long as one of these conditions is meet: - end is
 * reached = - - close is pressed = just kill thread all together!
 *
 * @author af
 *
 */
public class PerformAttackThread extends Thread {

    private AttackModel model; 	// refernce on attackModel
    private int min = 5;
    private int max = 50;
    private int delay;

    public PerformAttackThread(AttackModel model) {
	this.model = model;
    }

    // Always executed when start() is called
    public void run() {

	// Network stability test 
	// - only if enabled!
	if(this.model.getNetworkTestEnabled()){    
	    EventQueue.invokeLater(new UpdateAttackStateRunnable(this.model, 1));
	    for (int i = 0; i < this.model.getNetworkTestNumberRequests(); i++) {
		try {
		    // Send Request via new Thread
		    new SendRequestThread(this.model, 0, "networkTest");

		    // Wait X seconds as defined in model
		    Thread.sleep(this.model.getNetworkTestRequestInterval());
		} catch (InterruptedException e) {
		    System.out.println("interrupt in Sleep1");
		    Thread.currentThread().interrupt();
		    return;
		}
	    }

	    // Wait until all NetworkStabilityTest-Requests are done!!
	    // Via Loop that checks for "threadAbove" still running?
	    Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Waiting for all untampered requests to return"));
	    EventQueue.invokeLater(new UpdateAttackStateRunnable(this.model, 2));
	    while (this.model.getCounterRequestsSend("networkTest") != this.model.getNetworkTestNumberRequests() && !isInterrupted()) {
		try {
		    Thread.sleep(1000);
		} catch (InterruptedException e) {
		    this.interrupt();
		    return; // cheap way to end if interrupted!
		}
	    }
	    
	    // Write Coefficient_of_variation to Model and update GUI!
	    // - see http://en.wikipedia.org/wiki/Coefficient_of_variation
	    // - Update GUI...
	    EventQueue.invokeLater(new NetworktestResultRunnable(this.model));

	}
	
	// Start sending Untampered probes in Parallel
	this.model.setSendProbeRequestsThread(new RepeatTestprobeRequestThread(this.model));
	this.model.getSendProbeRequestsThread().start();

	// N x M untampered requests
	Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Start sending untampered requests to target"));
	EventQueue.invokeLater(new UpdateAttackStateRunnable(this.model, 2));
	model.setTsUntamperedStart(System.currentTimeMillis());	// Todo: Make nicer - even though it causes no problem
	for (int i = 0; i < this.model.getNumberThreads(); i++) {
	    // New Repeat-Request N-Times Object
	    new RepeatAttackRequestThread(model, i, "untampered");

	    // Update GUI with NumberRequestsSend
	    EventQueue.invokeLater(new UpdateNumberThreadsRunnable(this.model, "untampered"));
	    
	    // Delay start of next thread for a couple of ms to prevent sending at same time
	    try {
		delay = 5; // min + (int)(Math.random() * ((max - min) + 1));
		Thread.sleep(delay);
	    } catch (InterruptedException e) {
		this.interrupt();
		return; // cheap way to end if interrupted!
	    }
	}

	// Wait until all Untampered Requests are done!!
	// Via Loop that checks for "threadAbove" still running?
	Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Waiting for all untampered requests to return"));
	EventQueue.invokeLater(new UpdateAttackStateRunnable(this.model, 2));
	while (this.model.getCounterRequestsSend("untampered") != this.model.getRequestsTotal() && !isInterrupted()) {
	    try {
		Thread.sleep(1000);
	    } catch (InterruptedException e) {
		this.interrupt();
		return; // cheap way to end if interrupted!
	    }
	}

	// Server Recovery Time!
	// Wait X seconds, as passed by parameter
	Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Server recovery time"));
	EventQueue.invokeLater(new UpdateAttackStateRunnable(this.model, 3));
	try {
	    Thread.sleep(this.model.getSecondsServerLoadRecovery());
	} catch (InterruptedException e) {
	    this.interrupt();
	    return; // cheap way to end if interrupted!
	}


	// N x M tampered requests
	Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Start sending tampered requests to target"));
	EventQueue.invokeLater(new UpdateAttackStateRunnable(this.model, 4));
	model.setTsTamperedStart(System.currentTimeMillis());	// Todo: Make nicer - even though it causes no problem
	for (int i = 0; i < this.model.getNumberThreads(); i++) {
	    // New Repeat-Request N-Times Object
	    new RepeatAttackRequestThread(model, i, "tampered");

	    // Update GUI With Number Attack Threads started
	    EventQueue.invokeLater(new UpdateNumberThreadsRunnable(this.model, "tampered"));

	    // Delay start of next thread for a couple of ms to prevent sending at same time
	    try {
		delay = min + (int)(Math.random() * ((max - min) + 1));
		Thread.sleep(delay);
	    } catch (InterruptedException e) {
		this.interrupt();
		return; // cheap way to end if interrupted!
	    }	    
	}
	


	// Wait until all processes above are done!!
	// Via Loop that checks for "threadAbove" still running?
        Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Waiting for all tampered requests to return"));
	while (this.model.getCounterRequestsSend("tampered") != this.model.getRequestsTotal() && !isInterrupted()) {
	    try {
		Thread.sleep(1000);
	    } catch (InterruptedException e) {
		this.interrupt();
		return; // cheap way to end if interrupted!
	    }
	}

	
	// Is AutoFinalize switched on or off?
	if(model.isAutoFinalizeSwitch()){
	    EventQueue.invokeLater(new UpdateAttackStateRunnable(this.model, 9));
	    // Let Attack run for defined amount of time
	    try {
		Thread.sleep(model.getAutoFinalizeSeconds());
	    } catch (InterruptedException e) {
		this.interrupt();
		return; // cheap way to end if interrupted!
	    }	
	    
	    // finish attack by finilazing it!
	    Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Attack is done"));
	    Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Auto Finalization just started"));
	    EventQueue.invokeLater(new AutoFinalizeAttackRunnable(this.model));
	}else{	
	    // DONE, Finalize Button can now be enabled
	    // - again via custom runnable that is invoked via invokeLater
	    // - custom runnable calls model.updateStatus(X), that in return updates GUI!!
	    Result.getGlobalResult().add(new ResultEntry(ResultLevel.Info, getName(), "Attack is ready to be finalized"));
	    EventQueue.invokeLater(new UpdateAttackStateRunnable(this.model, 5));
	}
    }
}
