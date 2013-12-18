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
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.model.iface.Interface;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.List;
import javax.swing.JComboBox;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.testsuite.CurrentInterface;
import wsattacker.main.testsuite.TestSuite;

public class InterfaceComboBox extends JComboBox implements PropertyChangeListener {

	private static final long serialVersionUID = 1L;
	public static final String PROP_CONTROLLER = "controller";
	private ControllerInterface controller = null;
	private final transient PropertyChangeSupport propertyChangeSupport = new java.beans.PropertyChangeSupport(this);

	public InterfaceComboBox() {
		super();
		addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				if (controller != null && getSelectedIndex() >= 0) {
					controller.setCurrentService(getSelectedIndex());
				}
			}
		});
	}

	public void currentInterfaceChanged(WsdlInterface newService,
		WsdlInterface oldService) {
		final String name = (String) newService.getName();
		this.setSelectedItem(name);
	}

	public void noCurrentInterface() {
	}

	public void wsdlChanged(TestSuite testSuite) {
		List<Interface> list = testSuite.getProject().getInterfaceList();
		this.removeAllItems();
		if (list != null) {
			for (Interface service : list) {
				final String name = service.getName();
				this.addItem(name);
			}
		}
		if (this.getItemCount() > 0) {
			this.setEnabled(true);
		} else {
			this.setEnabled(false);
		}
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

		// remove old observer
		if (oldController != null) {
//			oldController.getTestSuite().getCurrentInterface().removeCurrentServiceObserver(this);
//			oldController.getTestSuite().removeCurrentWsdlChangeObserver(this);
			final TestSuite testSuite = oldController.getTestSuite();
			testSuite.getCurrentInterface().removePropertyChangeListener(CurrentInterface.PROP_WSDLINTERFACE, this);
			testSuite.removePropertyChangeListener(TestSuite.PROP_PROJECT, this);
		}
		// add new abserver
		if (this.controller != null) {
//			this.controller.getTestSuite().getCurrentInterface().addCurrentServiceObserver(this);
//			this.controller.getTestSuite().addCurrentWsdlChangeObserver(this);
			final TestSuite testSuite = oldController.getTestSuite();
			testSuite.getCurrentInterface().addPropertyChangeListener(CurrentInterface.PROP_WSDLINTERFACE, this);
			testSuite.addPropertyChangeListener(TestSuite.PROP_PROJECT, this);
		}

		propertyChangeSupport.firePropertyChange(PROP_CONTROLLER, oldController, controller);
	}

	@Override
	public void propertyChange(PropertyChangeEvent pce) {
		final String propName = pce.getPropertyName();
		if (CurrentInterface.PROP_WSDLINTERFACE.equals(propName)) {
			WsdlInterface newInterface = (WsdlInterface) pce.getNewValue();
			WsdlInterface oldInterface = (WsdlInterface) pce.getOldValue();
			if (newInterface == null) {
				noCurrentInterface();
			} else {
				currentInterfaceChanged(newInterface, oldInterface);
			}
		} else if (TestSuite.PROP_PROJECT.equals(propName)) {
			WsdlProject project = (WsdlProject) pce.getNewValue();
			List<Interface> list = project.getInterfaceList();
			this.removeAllItems();
			if (list != null) {
				for (Interface service : list) {
					final String name = service.getName();
					this.addItem(name);
				}
			}
			if (this.getItemCount() > 0) {
				this.setEnabled(true);
			} else {
				this.setEnabled(false);
			}

		}
	}
}
