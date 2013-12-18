/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.main.testsuite;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.jdesktop.beans.AbstractBean;
import wsattacker.main.composition.testsuite.CurrentOperationObserver;

/**
 * Holds a references to the currently used operation
 *
 * @author Christian Mainka
 *
 */
public class CurrentOperation extends AbstractBean implements PropertyChangeListener {

	final private static Logger LOG = Logger.getLogger(CurrentOperation.class);
	public static final String PROP_WSDLOPERATION = "wsdlOperation";
	private WsdlOperation wsdlOperation;
	private CurrentInterface currentInterface;
	final private List<CurrentOperationObserver> observers = new ArrayList<CurrentOperationObserver>();

	public CurrentOperation() {
	}

	public CurrentInterface getCurrentInterface() {
		return currentInterface;
	}

	public void setCurrentInterface(CurrentInterface newCurrentInterface) {
		final CurrentInterface oldInterface = this.currentInterface;
		if (oldInterface != null) {
			oldInterface.removePropertyChangeListener(this);
		}
		this.currentInterface = newCurrentInterface;
		if (newCurrentInterface != null) {
			newCurrentInterface.addPropertyChangeListener(CurrentInterface.PROP_WSDLINTERFACE, this);
		}
	}

	/**
	 * Get the value of wsdlOperation
	 *
	 * @return the value of wsdlOperation
	 */
	public WsdlOperation getWsdlOperation() {
		return wsdlOperation;
	}

	/**
	 * Set the value of wsdlOperation
	 *
	 * @param newWsdlOperation new value of wsdlOperation
	 */
	public void setWsdlOperation(WsdlOperation newWsdlOperation) {
		WsdlOperation oldWsdlOperation = this.wsdlOperation;
		this.wsdlOperation = newWsdlOperation;
		firePropertyChange(PROP_WSDLOPERATION, oldWsdlOperation, newWsdlOperation);
		notifyCurrentOperationObservers(newWsdlOperation, oldWsdlOperation);
	}

	@Override
	public void propertyChange(PropertyChangeEvent pce) {
		final String propName = pce.getPropertyName();
		if (TestSuite.PROP_CURRENTINTERFACE.equals(propName)) {
			LOG.info("Detected Service change");
			final CurrentInterface newCI = (CurrentInterface) pce.getNewValue();
			final WsdlInterface wsdlInterface = newCI.getWsdlInterface();
			if (wsdlInterface != null && wsdlInterface.getOperationCount() > 0) {
				// set default operation if any existing
				WsdlOperation operation = wsdlInterface.getOperationAt(0);
				LOG.info("Set default operation to: " + operation.getName());
				setWsdlOperation(operation);
			} else {
				setWsdlOperation(null);
			}
		}
	}

	@Deprecated
	/**
	 * This method will be removed in future version. Use the
	 * propertyChangeSupport instead.
	 */
	public void addCurrentOperationObserver(CurrentOperationObserver o) {
		observers.add(o);
	}

	@Deprecated
	/**
	 * This method will be removed in future version. Use the
	 * propertyChangeSupport instead.
	 */
	public void removeCurrentOperationObserver(CurrentOperationObserver o) {
		observers.remove(o);
	}

	private void notifyCurrentOperationObservers(WsdlOperation newOperation, WsdlOperation oldOperation) {
		if (newOperation == null) {
			for (CurrentOperationObserver o : observers) {
				o.noCurrentOperation();
			}
		} else {
			for (CurrentOperationObserver o : observers) {
				o.currentOperationChanged(newOperation, oldOperation);
			}
		}
	}
}
