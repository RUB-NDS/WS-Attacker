/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010  Christian Mainka
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package wsattacker.main.testsuite;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import wsattacker.main.composition.testsuite.CurrentInterfaceObserver;
import wsattacker.main.composition.testsuite.WsdlChangeObserver;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlProject;

/**
 * Holds a references to the currently used interface
 * @author Christian Mainka
 *
 */
public class CurrentInterface implements WsdlChangeObserver {
	private static Logger log = Logger.getLogger(CurrentInterface.class);
	
	List<CurrentInterfaceObserver> observers;
	WsdlInterface service;
	TestSuite testsuite;
	
	public CurrentInterface(TestSuite testsuite) {
		this.observers = new ArrayList<CurrentInterfaceObserver>();
		this.testsuite = testsuite;
		this.testsuite.addCurrentWsdlChangeObserver(this);
	}
	
	public void addCurrentServiceObserver(CurrentInterfaceObserver o) {
		observers.add(o);
	}
	
	public void removeCurrentServiceObserver(CurrentInterfaceObserver o) {
		observers.remove(o);
	}
	
	public void notifyCurrentServiceObservers(WsdlInterface newService, WsdlInterface oldService) {
		if(newService == null) {
			for(CurrentInterfaceObserver o : observers) {
				o.noCurrentInterface();
			}
		}
		else {
			for(CurrentInterfaceObserver o : observers) {
				o.currentInterfaceChanged(newService, oldService);
			}
		}
	}
	
	public WsdlInterface getWsdlService() {
		return service;
	}

	public void setWsdlService(WsdlInterface currentService) {
		WsdlInterface oldService = this.service;
		this.service = currentService;
		if(currentService != oldService) {
			notifyCurrentServiceObservers(currentService, oldService);
		}
	}

	@Override
	public void wsdlChanged(TestSuite testSuite) {
		log.info("Detected wsdl change");
		WsdlProject project = testSuite.getProject();
		if (project != null && project.getInterfaceCount() > 0) {
			// set default operation if any existing
			WsdlInterface service = (WsdlInterface) project.getInterfaceAt(0);
			log.info("Set default Service to: " + service.getName());
			setWsdlService(service);
		}
		else {
			setWsdlService(null);
		}
	}
}
