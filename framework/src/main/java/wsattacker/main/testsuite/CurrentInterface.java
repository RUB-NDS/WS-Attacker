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
package wsattacker.main.testsuite;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.jdesktop.beans.AbstractBean;
import wsattacker.main.composition.testsuite.CurrentInterfaceObserver;

/**
 * Holds a references to the currently used interface
 * 
 * @author Christian Mainka
 */
public class CurrentInterface
    extends AbstractBean
    implements PropertyChangeListener
{

    final private static Logger LOG = Logger.getLogger( CurrentInterface.class );

    public static final String PROP_WSDLINTERFACE = "wsdlInterface";

    private TestSuite testsuite;

    private WsdlInterface wsdlInterface;

    private TestSuite testSuite;

    final private List<CurrentInterfaceObserver> observers = new ArrayList<CurrentInterfaceObserver>();

    public CurrentInterface()
    {
    }

    public TestSuite getTestsuite()
    {
        return testsuite;
    }

    public void setTestsuite( TestSuite testsuite )
    {
        this.testsuite = testsuite;
    }

    public TestSuite getTestSuite()
    {
        return testSuite;
    }

    public void setTestSuite( TestSuite newTestSuite )
    {
        final TestSuite oldTestSuite = this.testSuite;
        if ( oldTestSuite != null )
        {
            oldTestSuite.removePropertyChangeListener( this );
        }
        this.testSuite = newTestSuite;
        if ( newTestSuite != null )
        {
            newTestSuite.addPropertyChangeListener( TestSuite.PROP_PROJECT, this );
        }
    }

    /**
     * Get the value of wsdlInterface
     * 
     * @return the value of wsdlInterface
     */
    public WsdlInterface getWsdlInterface()
    {
        return wsdlInterface;
    }

    /**
     * Set the value of wsdlInterface
     * 
     * @param newWsdlInterface new value of wsdlInterface
     */
    public void setWsdlInterface( WsdlInterface newWsdlInterface )
    {
        WsdlInterface oldWsdlInterface = this.wsdlInterface;
        this.wsdlInterface = newWsdlInterface;
        firePropertyChange( PROP_WSDLINTERFACE, oldWsdlInterface, newWsdlInterface );
        notifyCurrentServiceObservers( newWsdlInterface, oldWsdlInterface );
    }

    @Override
    public void propertyChange( PropertyChangeEvent pce )
    {
        final String propName = pce.getPropertyName();
        if ( TestSuite.PROP_PROJECT.equals( propName ) )
        {
            WsdlProject newProject = (WsdlProject) pce.getNewValue();
            if ( newProject != null && newProject.getInterfaceCount() > 0 )
            {
                WsdlInterface service = (WsdlInterface) newProject.getInterfaceAt( 0 );
                LOG.info( "Set default Service to: " + service.getName() );
                setWsdlInterface( wsdlInterface );
            }
        }
    }

    @Deprecated
    /**
     * This method will be removed in future version. Use the
     * propertyChangeSupport instead.
     */
    public void addCurrentServiceObserver( CurrentInterfaceObserver o )
    {
        observers.add( o );
    }

    @Deprecated
    /**
     * This method will be removed in future version. Use the
     * propertyChangeSupport instead.
     */
    public void removeCurrentServiceObserver( CurrentInterfaceObserver o )
    {
        observers.remove( o );
    }

    private void notifyCurrentServiceObservers( WsdlInterface newService, WsdlInterface oldService )
    {
        if ( newService == null )
        {
            for ( CurrentInterfaceObserver o : observers )
            {
                o.noCurrentInterface();
            }
        }
        else
        {
            for ( CurrentInterfaceObserver o : observers )
            {
                o.currentInterfaceChanged( newService, oldService );
            }
        }
    }
}
