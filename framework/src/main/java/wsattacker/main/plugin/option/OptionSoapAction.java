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
package wsattacker.main.plugin.option;

import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.model.iface.Operation;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import wsattacker.main.testsuite.CurrentOperation;
import wsattacker.main.testsuite.TestSuite;

public class OptionSoapAction extends OptionSimpleChoice implements PropertyChangeListener {

	private static final long serialVersionUID = 2L;
	final private static String MANUAL = "Manual Action";

	public OptionSoapAction(String name, String description) {
		super(name, description);
		clearChoices();
		setSelectedIndex(0);
		TestSuite.getInstance().getCurrentOperation().addPropertyChangeListener(CurrentOperation.PROP_WSDLOPERATION, this);
	}

	private void clearChoices() {
		List<String> newChoices = new ArrayList<String>();
		newChoices.add(MANUAL);
		setChoices(newChoices);
	}

	private void currentOperationChanged(WsdlOperation newOperation,
		WsdlOperation oldOperation) {
		final List<Operation> operationList = newOperation.getInterface().getOperationList();
		final List<String> newChoices = new ArrayList<String>(operationList.size());
		for (Operation operation : operationList) {
			final String name = operation.getName();
			newChoices.add(name);
		}
		if (newOperation.getName().equals(getValueAsString())) {
			setSelectedIndex(0);
		}
		setChoices(newChoices);
	}

	private void noCurrentOperation() {
		clearChoices();
		setSelectedIndex(0);
	}

	@Override
	public void propertyChange(PropertyChangeEvent pce) {
		final String propName = pce.getPropertyName();
		if (CurrentOperation.PROP_WSDLOPERATION.equals(propName)) {
			final WsdlOperation newOperation = (WsdlOperation) pce.getNewValue();
			if (newOperation == null) {
				noCurrentOperation();
			}
			final WsdlOperation oldOperation = (WsdlOperation) pce.getOldValue();
			currentOperationChanged(newOperation, oldOperation);
		}
	}
}
