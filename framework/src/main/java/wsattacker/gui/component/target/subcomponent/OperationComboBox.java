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
package wsattacker.gui.component.target.subcomponent;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.model.iface.Operation;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import javax.swing.JComboBox;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.testsuite.CurrentInterface;
import wsattacker.main.testsuite.CurrentOperation;
import wsattacker.main.testsuite.TestSuite;

public class OperationComboBox extends JComboBox implements PropertyChangeListener {

	private static final long serialVersionUID = 1L;
	public static final String PROP_CONTROLLER = "controller";
	private ControllerInterface controller;
	private final transient PropertyChangeSupport propertyChangeSupport = new java.beans.PropertyChangeSupport(this);

	public OperationComboBox() {
		super();
		addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				if (controller != null && getSelectedIndex() >= 0) {
					controller.setCurrentOperation(getSelectedIndex());
				}
			}
		});
	}

	public void currentInterfaceChanged(WsdlInterface newService,
		WsdlInterface oldService) {
		this.removeAllItems();
		if (newService.getOperationList() != null) {
			for (Operation operation : newService.getOperationList()) {
				this.addItem(operation.getName());
			}
		}
		if (this.getItemCount() > 0) {
			this.setEnabled(true);
		} else {
			this.setEnabled(false);
		}
	}

	public void noCurrentInterface() {
		this.removeAllItems();
		this.setEnabled(false);
	}

	public void currentOperationChanged(WsdlOperation newOperation,
		WsdlOperation oldOperation) {
		this.setSelectedItem((String) newOperation.getName());
	}

	public void noCurrentOperation() {
		// nothing to do
	}

	/**
	 * @return the controller
	 */
	public ControllerInterface getController() {
		return controller;
	}

	/**
	 * @param controller the controller to set
	 */
	public void setController(ControllerInterface controller) {
		wsattacker.main.composition.ControllerInterface oldController = controller;
		this.controller = controller;
		if (oldController != null) {
			final TestSuite testSuite = oldController.getTestSuite();
//			testSuite.getCurrentInterface().removeCurrentServiceObserver(this);
//			testSuite.getCurrentOperation().removeCurrentOperationObserver(this);
			testSuite.getCurrentInterface().removePropertyChangeListener(CurrentInterface.PROP_WSDLINTERFACE, this);
			testSuite.getCurrentOperation().removePropertyChangeListener(CurrentOperation.PROP_WSDLOPERATION, this);
		}
		if (this.controller != null) {
			final TestSuite testSuite = this.controller.getTestSuite();
//			testSuite.getCurrentInterface().addCurrentServiceObserver(this);
//			testSuite.getCurrentOperation().addCurrentOperationObserver(this);
			testSuite.getCurrentInterface().addPropertyChangeListener(CurrentInterface.PROP_WSDLINTERFACE, this);
			testSuite.getCurrentOperation().addPropertyChangeListener(CurrentOperation.PROP_WSDLOPERATION, this);
		}
		propertyChangeSupport.firePropertyChange(PROP_CONTROLLER, oldController, controller);
	}

	@Override
	public void propertyChange(PropertyChangeEvent pce) {
		final String propName = pce.getPropertyName();
		if (CurrentInterface.PROP_WSDLINTERFACE.equals(propName)) {
			final WsdlInterface newInterface = (WsdlInterface) pce.getNewValue();
			final WsdlInterface oldInterface = (WsdlInterface) pce.getOldValue();
			if (newInterface == null) {
				noCurrentInterface();
			} else {
				currentInterfaceChanged(newInterface, oldInterface);
			}
		} else if (CurrentOperation.PROP_WSDLOPERATION.equals(propName)) {
			final WsdlOperation newOperation = (WsdlOperation) pce.getNewValue();
			final WsdlOperation oldOperation = (WsdlOperation) pce.getOldValue();
			currentOperationChanged(newOperation, oldOperation);
		}
	}
}
