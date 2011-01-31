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

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.apache.log4j.Logger;

import wsattacker.gui.util.MultiLineTableCellRenderer;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.composition.testsuite.CurrentRequestObserver;
import wsattacker.main.testsuite.TestSuite;
import wsattacker.util.SoapUtilities;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.model.iface.Request;

public class RequestInputTable extends JTable {
	private static final long serialVersionUID = 1L;
	RequestTableModel model = null;

	// only for jiglo
	public RequestInputTable() {
	}

	public RequestInputTable(ControllerInterface controller) {
		setVisible(true);
		model = new RequestTableModel(controller);
		setModel(model);
		this.getColumnModel().getColumn(0).setPreferredWidth(50);
		this.getColumnModel().getColumn(1).setPreferredWidth(300);
		this.getColumnModel().getColumn(1).setCellRenderer(new MultiLineTableCellRenderer());
		this.getColumnModel().getColumn(2).setPreferredWidth(100);
	}

	public class RequestTableModel extends AbstractTableModel implements
			CurrentRequestContentChangeObserver, CurrentRequestObserver {

		private static final long serialVersionUID = 1L;
		final private String[] columnNames = { "Name", "Parents", "Value" };
		private List<SOAPElement> list;
		private ControllerInterface controller;

		public RequestTableModel(ControllerInterface controller) {
			this.list = new ArrayList<SOAPElement>();
			this.controller = controller;
			TestSuite.getInstance().getCurrentRequest()
					.addCurrentRequestContentObserver(this);
			TestSuite.getInstance().getCurrentRequest()
					.addCurrentRequestObserver(this);

		}

		public int getColumnCount() {
			return this.columnNames.length;
		}

		public int getRowCount() {
			return list.size();
		}

		public String getColumnName(int num) {
			return this.columnNames[num];
		}

		public boolean isCellEditable(int y, int x) {
			if (x == 2) {
				return true;
			}
			return false;
		}

		public Object getValueAt(int row, int col) {
			if (col == 0) {
				// return name
				return this.list.get(row).getNodeName();
			} else if (col == 1) {
				// return parents
				List<SOAPElement> parents = SoapUtilities.getParents(this.list
						.get(row));
				StringBuffer buffer = new StringBuffer();
				for (SOAPElement e : parents) {
					buffer.insert(0, e.getNodeName() + " -> ");
				}
				buffer.delete(buffer.length() - 4, buffer.length());
				return buffer.toString();
			} else if (col == 2) {
				// return value
				return this.list.get(row).getTextContent();
			}

			return null;
		}

		public void setValueAt(Object value, int row, int col) {
			String newValue = (String) value;
			SOAPElement theElement = this.list.get(row);
			theElement.setTextContent(newValue);
			Logger log = Logger.getLogger(getClass());
			log.trace(String.format("Set Value @ (%d,%d) --> %s='%s'", row,
					col, theElement.getNodeName(), newValue));
			if (controller != null) {
				controller.setRequestContent(getRequestContent());
			}
		}

		public List<SOAPElement> getData() {
			return list;
		}

		public void setData(Request request) throws SOAPException {
			setData(request.getRequestContent());
		}

		public void setData(String request) throws SOAPException {
			SOAPMessage msg = SoapUtilities.stringToSoap(request);
			List<SOAPElement> list = SoapUtilities.inputNeeded(msg
					.getSOAPPart().getEnvelope());
			setData(list);

		}

		public void setData(List<SOAPElement> list) {
			if (list == null) {
				return;
			}
			this.list = list;
			this.fireTableDataChanged();
		}

		public SOAPElement getRequestRoot() {
			if (list.size() > 0) {
				// all input elements have the same root, no support for
				// multi-roots, but this is okay, since we assume a legit
				// messages at this point
				return SoapUtilities.getRoot(list.get(0));
			}
			return null;
		}

		public String getRequestContent() {
			SOAPElement root = getRequestRoot();
			if (root == null) {
				return ""; // no root = empty message content
			}
			return SoapUtilities.soapToString(root);
		}

		@Override
		public void currentRequestChanged(WsdlRequest newRequest,
				WsdlRequest oldRequest) {
			try {
				setData(newRequest);
			} catch (SOAPException e) {
				Logger.getLogger(getClass()).error(
						"Invalid Request " + e.getMessage()!=null?e.getMessage():"");
				// e.printStackTrace();
			} catch (Exception e) {
				Logger.getLogger(getClass()).error(
						"Unknown Error: Invalid Request " + e.getMessage()!=null?e.getMessage():"");
			}
		}

		@Override
		public void currentRequestContentChanged(String newContent,
				String oldContent) {
			try {
				setData(newContent);
			} catch (SOAPException e) {
				Logger.getLogger(getClass()).error(
						"Invalid Request " + e.getMessage()!=null?e.getMessage():"");
				// e.printStackTrace();
			} catch (Exception e) {
				Logger.getLogger(getClass()).error(
						"Unknown Error: Invalid Request " + e.getMessage()!=null?e.getMessage():"");
			}
		}

		@Override
		public void noCurrentRequest() {
			setData(new ArrayList<SOAPElement>());
		}

		@Override
		public void noCurrentRequestontent() {
			setData(new ArrayList<SOAPElement>());
		}
	}
}
