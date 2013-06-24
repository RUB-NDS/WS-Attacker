/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2012  Christian Mainka
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
import com.eviware.soapui.model.iface.Request;
import java.beans.PropertyChangeSupport;
import java.util.HashMap;
import java.util.Map;
import javax.swing.table.AbstractTableModel;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import org.apache.log4j.Logger;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.composition.testsuite.CurrentRequestObserver;
import wsattacker.main.testsuite.TestSuite;
import wsattacker.util.SoapUtilities;

/**
 *
 * @author christian
 */
public class NamespaceTableModel extends AbstractTableModel implements CurrentRequestContentChangeObserver, CurrentRequestObserver {
    private static final long serialVersionUID = 1L;
    public static final String PROP_CONTROLLER = "PROP_CONTROLLER";
    private String[] columnNames = {"Prefix", "Uri"};
    private Map<String, String> content = new HashMap<String, String>();
    private ControllerInterface controller = null;
    private final transient PropertyChangeSupport propertyChangeSupport = new java.beans.PropertyChangeSupport(this);

    public NamespaceTableModel() {
    }

    @Override
    public int getColumnCount() {
        return this.columnNames.length;
    }

    @Override
    public int getRowCount() {
        return content.size();
    }

    @Override
    public String getColumnName(int num) {
        return this.columnNames[num];
    }

    @Override
    public boolean isCellEditable(int y, int x) {
        //			if(x == 1){
        //				return true;
        //			}
        return false;
    }

    @Override
    public Object getValueAt(int y, int x) {
        if (content.isEmpty()) {
            return null;
        }
        Object[] keyArray = this.content.keySet().toArray();
        if (x == 0) {
            return keyArray[y].toString();
        } else if (x == 1) {
            return this.content.get(keyArray[y]).toString();
        }
        return null;
    }

    public void setNamespaceData(Request request) throws SOAPException {
        setNamespaceData(request.getRequestContent());
    }

    public void setNamespaceData(String request) throws SOAPException {
        SOAPMessage msg = SoapUtilities.stringToSoap(request);
        Map<String, String> namespaces = SoapUtilities.allNamespaces(msg.getSOAPPart().getEnvelope());
        setNamespaceData(namespaces);
    }

    public void setNamespaceData(Map<String, String> nsContent) {
        if (nsContent == null) {
            return;
        }
        this.content = nsContent;
        this.fireTableDataChanged();
    }

    @Override
    public void currentRequestChanged(WsdlRequest newRequest, WsdlRequest oldRequest) {
        try {
            setNamespaceData(newRequest);
        }
        catch (SOAPException e) {
            Logger.getLogger(getClass()).warn("Invalid Request: " + e.getMessage());
            //				e.printStackTrace();
        }
    }

    @Override
    public void currentRequestContentChanged(String newContent, String oldContent) {
        try {
            setNamespaceData(newContent);
        }
        catch (SOAPException e) {
            Logger.getLogger(getClass()).warn("Invalid Request: " + e.getMessage());
            //				e.printStackTrace();
        }
    }

    @Override
    public void noCurrentRequest() {
        setNamespaceData(new HashMap<String, String>());
    }

    @Override
    public void noCurrentRequestcontent() {
        setNamespaceData(new HashMap<String, String>());
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
            oldController.getTestSuite().getCurrentRequest().removeCurrentRequestContentObserver(this);
            oldController.getTestSuite().getCurrentRequest().removeCurrentRequestObserver(this);
        }
        if (this.controller != null) {
            this.controller.getTestSuite().getCurrentRequest().addCurrentRequestContentObserver(this);
            this.controller.getTestSuite().getCurrentRequest().addCurrentRequestObserver(this);
        }
        propertyChangeSupport.firePropertyChange(PROP_CONTROLLER, oldController, controller);
    }

}
