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

import java.util.List;

import javax.swing.JComboBox;

import wsattacker.main.composition.testsuite.CurrentInterfaceObserver;
import wsattacker.main.composition.testsuite.WsdlChangeObserver;
import wsattacker.main.testsuite.TestSuite;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.model.iface.Interface;

public class InterfaceComboBox extends JComboBox implements CurrentInterfaceObserver, WsdlChangeObserver {
	
	private static final long serialVersionUID = 1L;

	public InterfaceComboBox() {
		super();
		TestSuite.getInstance().getCurrentService().addCurrentServiceObserver(this);
		TestSuite.getInstance().addCurrentWsdlChangeObserver(this);
	}

	@Override
	public void currentInterfaceChanged(WsdlInterface newService,
			WsdlInterface oldService) {
		this.setSelectedItem((String) newService.getName());
	}

	@Override
	public void noCurrentInterface() {
	}

	@Override
	public void wsdlChanged(TestSuite testSuite) {
		List<Interface> list = testSuite.getProject().getInterfaceList();
		this.removeAllItems();
		if (list != null) {
			for (Interface service : list) {
				this.addItem(service.getName());
			}
		}
		if (this.getItemCount() > 0) {
			this.setEnabled(true);
		} else {
			this.setEnabled(false);
		}
	}
}
