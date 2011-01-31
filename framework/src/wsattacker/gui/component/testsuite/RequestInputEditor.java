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

package wsattacker.gui.component.testsuite;

import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

import wsattacker.gui.util.XmlTextPane;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.composition.testsuite.CurrentRequestObserver;
import wsattacker.main.testsuite.TestSuite;

import com.eviware.soapui.impl.wsdl.WsdlRequest;

public class RequestInputEditor extends XmlTextPane  implements CurrentRequestContentChangeObserver, CurrentRequestObserver {
	private static final long serialVersionUID = 1L;
	private ControllerInterface controller;
	
	public RequestInputEditor() {
		this.setEditable(true);
		this.setText("");
		TestSuite.getInstance().getCurrentRequest().addCurrentRequestContentObserver(this);
		TestSuite.getInstance().getCurrentRequest().addCurrentRequestObserver(this);
	}
	public RequestInputEditor(ControllerInterface controller) {
		this();
		this.controller = controller;
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
	
	private void saveContent() {
		String content = this.getText();
		if(controller != null ) {
			controller.setRequestContent(content);
		}
	}
	
	private void updateContent(String content) {
		this.setText(content);
	}
	
	@Override
	public void currentRequestChanged(WsdlRequest newRequest,
			WsdlRequest oldRequest) {
		updateContent(newRequest.getRequestContent());
		setEnabled(true);
	}

	@Override
	public void noCurrentRequest() {
		updateContent("");
		setEnabled(false);
	}

	@Override
	public void currentRequestContentChanged(String newContent,
			String oldContent) {
		updateContent(newContent);
		setEnabled(true);
	}

	@Override
	public void noCurrentRequestontent() {
		updateContent("");
		setEnabled(false);
	}

}
