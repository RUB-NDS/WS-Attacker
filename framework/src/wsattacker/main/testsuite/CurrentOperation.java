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

import wsattacker.main.composition.testsuite.CurrentOperationObserver;
import wsattacker.main.composition.testsuite.CurrentInterfaceObserver;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;

/**
 * Holds a references to the currently used operation
 * @author Christian Mainka
 *
 */
public class CurrentOperation implements CurrentInterfaceObserver {
	private static Logger log = Logger.getLogger(CurrentOperation.class);
	
	List<CurrentOperationObserver> observers;
	WsdlOperation currentOperation;
	TestSuite testsuite;
	
	public CurrentOperation(TestSuite testsuite) {
		this.observers = new ArrayList<CurrentOperationObserver>();
		this.testsuite = testsuite;
		this.testsuite.getCurrentService().addCurrentServiceObserver(this);
	}
	
	public void addCurrentOperationObserver(CurrentOperationObserver o) {
		observers.add(o);
	}
	
	public void removeCurrentOperationObserver(CurrentOperationObserver o) {
		observers.remove(o);
	}
	
	public void notifyCurrentOperationObservers(WsdlOperation newOperation, WsdlOperation oldOperation) {
		if(newOperation == null) {
			for(CurrentOperationObserver o : observers) {
				o.noCurrentOperation();
			}
		}
		else {
			for(CurrentOperationObserver o : observers) {
				o.currentOperationChanged(newOperation, oldOperation);
			}
		}
	}

	public WsdlOperation getWsdlOperation() {
		return currentOperation;
	}

	public void setWsdlOperation(WsdlOperation currentOperation) {
		WsdlOperation oldOperation = this.currentOperation;
		this.currentOperation = currentOperation;
		if(currentOperation != oldOperation) {
			notifyCurrentOperationObservers(currentOperation, oldOperation);
		}
	}

	@Override
	public void currentInterfaceChanged(WsdlInterface newService, WsdlInterface oldService) {
		log.info("Detected Service change");
		if (newService.getOperationCount() > 0) {
			// set default operation if any existing
			WsdlOperation operation = newService.getOperationAt(0);
			log.info("Set default operation to: " + operation.getName());
			setWsdlOperation(operation);
		}
		else {
			setWsdlOperation(null);
		}
	}

	@Override
	public void noCurrentInterface() {
		setWsdlOperation(null);
	}
}
