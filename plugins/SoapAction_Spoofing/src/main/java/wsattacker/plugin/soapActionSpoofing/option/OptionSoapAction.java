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
package wsattacker.plugin.soapActionSpoofing.option;

import java.util.ArrayList;
import java.util.List;

import wsattacker.main.composition.plugin.option.AbstractOptionChoice;
import wsattacker.main.composition.testsuite.CurrentOperationObserver;
import wsattacker.main.testsuite.TestSuite;

import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.model.iface.Operation;

public class OptionSoapAction extends AbstractOptionChoice implements CurrentOperationObserver {
	private static final long serialVersionUID = 1L;
	List<String> choices;
	String selected;
	final String MANUAL = "Manual Action";

	public OptionSoapAction(String name, String description) {
		super(name, description);
		choices = new ArrayList<String>();
		clearChoices();
		setChoice(0);
		TestSuite.getInstance().getCurrentOperation().addCurrentOperationObserver(this);
	}
	
	private void clearChoices() {
		choices.clear();
		choices.add(MANUAL);
	}

	@Override
	public List<String> getChoices() {
		return choices;
	}

	@Override
	public boolean setChoice(String value) {
		if(isValid(value)) {
			selected = value;
			notifyValueChanged();
			return true;
		}
		return false;
	}

	@Override
	public boolean setChoice(int index) {
		if(isValid(index)) {
			selected = choices.get(index);
			notifyValueChanged();
			return true;
		}
		return false;
	}

	@Override
	public int getChoice() {
		return choices.indexOf(selected);
	}

	@Override
	public boolean isValid(String value) {
		return (value==null) || choices.contains(value);
	}

	@Override
	public boolean isValid(int choice) {
		return (choice >= -1) && (choice < choices.size());
	}

	@Override
	public boolean parseValue(String value) {
		return setChoice(value);
	}

	@Override
	public String getValueAsString() {
		return selected;
	}

	@Override
	public void currentOperationChanged(WsdlOperation newOperation,
			WsdlOperation oldOperation) {
		// do we have a complete new list of operations?
//		if( oldOperation == null || newOperation.getInterface() != oldOperation.getInterface()) {
//			choices.clear();
//			choices.add(MANUAL);
//			for(Operation operation : newOperation.getInterface().getOperationList()) {
//				choices.add(operation.getName());
//			}
//		}
//		if(newOperation.getName().equals(getValueAsString())) {
//			setChoice(-1);
//		}
//		choices.remove(newOperation.getName());
//		if(oldOperation != null && (oldOperation.getInterface() == newOperation.getInterface())) {
//			choices.add(oldOperation.getName());
//		}
//		notifyValueChanged();
		
		clearChoices();
		for(Operation operation : newOperation.getInterface().getOperationList()) {
			choices.add(operation.getName());
		}
		if(newOperation.getName().equals(getValueAsString())) {
			setChoice(0);
		}
		choices.remove(newOperation.getName());
		notifyValueChanged();
	}

	@Override
	public void noCurrentOperation() {
		choices.clear();
		setChoice(0);
	}

}
