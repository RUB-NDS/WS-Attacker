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
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import javax.swing.JTextField;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.testsuite.CurrentInterface;
import wsattacker.main.testsuite.TestSuite;

public class WsdlInputField
    extends JTextField
    implements PropertyChangeListener
{

    private static final long serialVersionUID = 1L;

    public static final String PROP_CONTROLLER = "controller";

    private ControllerInterface controller;

    public WsdlInputField()
    {
        setText( "http://192.168.254.201:8080/axis2/services/WebserviceOperations?wsdl" );
        setText( "http://bender.fritz.box:8080/WebServiceTest/wsdl/Addition.wsdl" );
        // TestSuite.getInstance().getCurrentService().addCurrentServiceObserver(this);
    }

    public void currentInterfaceChanged( WsdlInterface newService, WsdlInterface oldService )
    {
        String newUri = newService.getDefinition();
        if ( newUri != null )
        {
            setText( newUri );
        }
    }

    public void noCurrentInterface()
    {
    }

    /**
     * @return the controller
     */
    public ControllerInterface getController()
    {
        return controller;
    }

    /**
     * @param controller the controller to set
     */
    public void setController( ControllerInterface controller )
    {
        wsattacker.main.composition.ControllerInterface oldController = controller;
        this.controller = controller;
        if ( oldController != null )
        {
            final TestSuite testSuite = this.controller.getTestSuite();
            // testSuite.getCurrentInterface().removeCurrentServiceObserver(this);
            testSuite.getCurrentInterface().removePropertyChangeListener( CurrentInterface.PROP_WSDLINTERFACE, this );
        }
        if ( this.controller != null )
        {
            final TestSuite testSuite = this.controller.getTestSuite();
            // testSuite.getCurrentInterface().addCurrentServiceObserver(this);
            testSuite.getCurrentInterface().addPropertyChangeListener( CurrentInterface.PROP_WSDLINTERFACE, this );
        }
        firePropertyChange( PROP_CONTROLLER, oldController, controller );
    }

    @Override
    public void propertyChange( PropertyChangeEvent pce )
    {
        final String propName = pce.getPropertyName();
        if ( propName.equals( CurrentInterface.PROP_WSDLINTERFACE ) )
        {
            final WsdlInterface newInterface = (WsdlInterface) pce.getNewValue();
            final WsdlInterface oldInterface = (WsdlInterface) pce.getOldValue();
            if ( newInterface == null )
            {
                noCurrentInterface();
            }
            else
            {
                currentInterfaceChanged( newInterface, oldInterface );
            }
        }
    }
}
