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

import java.util.HashMap;
import java.util.Map;

import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.apache.log4j.Logger;

import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.composition.testsuite.CurrentRequestObserver;
import wsattacker.main.testsuite.TestSuite;
import wsattacker.util.SoapUtilities;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.model.iface.Request;

public class NamespaceTable extends JTable {
	private static final long serialVersionUID = 1L;
	NamespaceTableModel model;
	public NamespaceTable() {
		super();
		setVisible(true);
		model = new NamespaceTableModel();
		setModel(model);
	}
	
	public class NamespaceTableModel extends AbstractTableModel implements CurrentRequestContentChangeObserver, CurrentRequestObserver{

		private static final long serialVersionUID = 1L;
		private String[] columnNames = {"Prefix", "Uri"};
		private Map<String,String> content = new HashMap<String, String>();
		
		public NamespaceTableModel() {
			TestSuite.getInstance().getCurrentRequest().addCurrentRequestContentObserver(this);
			TestSuite.getInstance().getCurrentRequest().addCurrentRequestObserver(this);
		}

		public int getColumnCount() {
			return this.columnNames.length;
		}

		public int getRowCount() {
			return content.size();
		}

		public String getColumnName(int num){
			return this.columnNames[num];
		}

		public boolean isCellEditable(int y, int x){
//			if(x == 1){
//				return true;
//			}
			return false;
		}

		public Object getValueAt(int y, int x) {
			if (content.size() == 0)
				return null;
			Object[] keyArray = this.content.keySet().toArray();

			if(x == 0){
				 return keyArray[y].toString();
			} else if(x == 1){
				return this.content.get(keyArray[y]).toString();
			}

			return null;
		}
		
		public void setNamespaceData(Request request) throws SOAPException {
			setNamespaceData(request.getRequestContent());
		}

		public void setNamespaceData(String request) throws SOAPException {
			SOAPMessage msg = SoapUtilities.stringToSoap(request);
			Map<String,String> namespaces = SoapUtilities.allNamespaces(msg.getSOAPPart().getEnvelope());
			setNamespaceData(namespaces);
			
		}
		
		public void setNamespaceData(Map<String,String> nsContent){
			if(nsContent == null){
				return;
			}
			this.content = nsContent;
			this.fireTableDataChanged();
		}

		@Override
		public void currentRequestChanged(WsdlRequest newRequest,
				WsdlRequest oldRequest) {
			try {
				setNamespaceData(newRequest);
			} catch (SOAPException e) {
				Logger.getLogger(getClass()).warn("Invalid Request: " + e.getMessage());
//				e.printStackTrace();
			}
		}

		@Override
		public void currentRequestContentChanged(String newContent,
				String oldContent) {
			try {
				setNamespaceData(newContent);
			} catch (SOAPException e) {
				Logger.getLogger(getClass()).warn("Invalid Request: " + e.getMessage());
//				e.printStackTrace();
			}
		}

		@Override
		public void noCurrentRequest() {
			setNamespaceData(new HashMap<String,String>());
		}

		@Override
		public void noCurrentRequestontent() {
			setNamespaceData(new HashMap<String,String>());
		}
	}
}
