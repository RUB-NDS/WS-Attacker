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

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import wsattacker.gui.util.XmlTextPane;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.testsuite.CurrentRequest;
import wsattacker.main.testsuite.TestSuite;

public class RequestInputEditor extends XmlTextPane implements PropertyChangeListener {

	private static final long serialVersionUID = 1L;
	public static final String PROP_CONTROLLER = "controller";
	private ControllerInterface controller = null;
	private final transient PropertyChangeSupport propertyChangeSupport = new java.beans.PropertyChangeSupport(this);

	public RequestInputEditor() {
		this.setEditable(true);
		this.setText("");
	}

	private void saveContent() {
		String content = this.getText();
		if (getController() != null) {
			getController().setRequestContent(content);
		}
	}

	private void updateContent(String content) {
		this.setText(content);
	}

	public void currentRequestChanged(WsdlRequest newRequest,
		WsdlRequest oldRequest) {
		updateContent(newRequest.getRequestContent());
		setEnabled(true);
	}

	public void noCurrentRequest() {
		updateContent("");
		setEnabled(false);
	}

	public void currentRequestContentChanged(String newContent,
		String oldContent) {
		updateContent(newContent);
		setEnabled(true);
	}

	public void noCurrentRequestcontent() {
		updateContent("");
		setEnabled(false);
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
//			oldController.getTestSuite().getCurrentRequest().removeCurrentRequestObserver(this);
//			oldController.getTestSuite().getCurrentRequest().removeCurrentRequestContentObserver(this);
			oldController.getTestSuite().getCurrentRequest().removePropertyChangeListener(this);
		}
		if (this.controller != null) {
//			this.controller.getTestSuite().getCurrentRequest().addCurrentRequestObserver(this);
//			this.controller.getTestSuite().getCurrentRequest().addCurrentRequestContentObserver(this);
			final TestSuite testSuite = this.controller.getTestSuite();
			testSuite.getCurrentRequest().addPropertyChangeListener(CurrentRequest.PROP_WSDLREQUEST, this);
			testSuite.getCurrentRequest().addPropertyChangeListener(CurrentRequest.PROP_WSDLREQUESTCONTENT, this);
			this.addFocusListener(new FocusListener() {
				@Override
				public void focusLost(FocusEvent e) {
					saveContent();
				}

				@Override
				public void focusGained(FocusEvent e) {
				}
			});
		}
		propertyChangeSupport.firePropertyChange(PROP_CONTROLLER, oldController, controller);
	}

	@Override
	public void propertyChange(PropertyChangeEvent pce) {
		final String propName = pce.getPropertyName();
		if (propName.equals(CurrentRequest.PROP_WSDLREQUEST)) {
			final WsdlRequest newRequest = (WsdlRequest) pce.getNewValue();
			final WsdlRequest oldRequest = (WsdlRequest) pce.getOldValue();
			if (newRequest == null) {
				noCurrentRequest();
			} else {
				currentRequestChanged(newRequest, oldRequest);
			}
		} else if (propName.equals(CurrentRequest.PROP_WSDLREQUESTCONTENT)) {
			final String newContent = (String) pce.getNewValue();
			final String oldContent = (String) pce.getOldValue();
			if (newContent == null) {
				noCurrentRequestcontent();
			} else {
				currentRequestContentChanged(newContent, oldContent);
			}
		}
	}
}
