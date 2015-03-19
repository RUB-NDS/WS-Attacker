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

import com.eviware.soapui.impl.WsdlInterfaceFactory;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlProjectFactory;
import com.eviware.soapui.support.SoapUIException;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.jdesktop.beans.AbstractBean;
import wsattacker.main.composition.testsuite.WsdlChangeObserver;

/**
 * TestSuite for WS-Attacker Provides methods for loading a WSDL and selection operations
 * 
 * @author Christian Mainka
 */
final public class TestSuite
    extends AbstractBean
{

    private static final TestSuite instance = new TestSuite();

    private static final Logger LOG = Logger.getLogger( TestSuite.class );

    public static final String PROP_PROJECT = "project";

    public static final String PROP_CURRENTINTERFACE = "currentInterface";

    public static final String PROP_CURRENTOPERATION = "currentOperation";

    public static final String PROP_CURRENTREQUEST = "currentRequest";

    public static TestSuite getInstance()
    {
        return instance;
    }

    final private List<WsdlChangeObserver> wsdlChangeObserver = new ArrayList<WsdlChangeObserver>();

    private WsdlProject project;

    private CurrentInterface currentInterface;

    private CurrentOperation currentOperation;

    private CurrentRequest currentRequest;

    public TestSuite()
    {
        this.project = createEmptyProject();
        this.currentInterface = new CurrentInterface();
        this.currentInterface.setTestSuite( this );
        this.currentOperation = new CurrentOperation();
        this.currentOperation.setCurrentInterface( currentInterface );
        this.currentRequest = new CurrentRequest();
        this.currentRequest.setCurrentOperation( currentOperation );
    }

    // projects are needed for soapui but not for ws-attacker, since we have our
    // own projects
    private WsdlProject createEmptyProject()
    {
        WsdlProject project = null;
        WsdlProjectFactory fac = new WsdlProjectFactory();
        try
        {
            project = fac.createNew();
        }
        catch ( XmlException e )
        {
            LOG.fatal( "Could not Instanciate WsdlProject: " + e.getMessage() );
        }
        catch ( IOException e )
        {
            LOG.fatal( "Could not Instanciate WsdlProject: " + e.getMessage() );
        }
        catch ( SoapUIException e )
        {
            LOG.fatal( "Could not Instanciate WsdlProject: " + e.getMessage() );
        }
        return project;
    }

    public void loadWsdl( String url )
        throws SoapUIException, MalformedURLException
    {
        assert ( this.getProject() != null );
        if ( url.length() > 0 )
        {
            // convert string to uri
            if ( new File( url ).exists() )
            {
                url = new File( url ).toURI().toURL().toString();
            }

            if ( url.toUpperCase().endsWith( "WADL" ) )
            {
                throw new UnsupportedOperationException( "WADL not yet supported" );
            }
            else
            {
                importWsdl( url );
            }
        }
    }

    private void importWsdl( String url )
        throws SoapUIException
    {
        WsdlProject project = createEmptyProject();
        WsdlInterfaceFactory.importWsdl( project, url, false ); // import wsdl
        setProject( project );
        LOG.info( "Successfully loaded wsdl" );

    }

    public WsdlProject getProject()
    {
        return project;
    }

    protected void setProject( WsdlProject newProject )
    {
        WsdlProject oldProject = this.project;
        this.project = newProject;
        firePropertyChange( PROP_PROJECT, oldProject, newProject );
        notifyCurrentWsdlChangeObservers();
    }

    public CurrentInterface getCurrentInterface()
    {
        return currentInterface;
    }

    protected void setCurrentInterface( CurrentInterface newCurrentInterface )
    {
        CurrentInterface oldCurrentInterface = this.currentInterface;
        this.currentInterface = newCurrentInterface;
        firePropertyChange( PROP_CURRENTINTERFACE, oldCurrentInterface, newCurrentInterface );
    }

    public CurrentOperation getCurrentOperation()
    {
        return currentOperation;
    }

    protected void setCurrentOperation( CurrentOperation newCurrentOperation )
    {
        CurrentOperation oldCurrentOperation = this.currentOperation;
        this.currentOperation = newCurrentOperation;
        firePropertyChange( PROP_CURRENTOPERATION, oldCurrentOperation, newCurrentOperation );
    }

    public CurrentRequest getCurrentRequest()
    {
        return currentRequest;
    }

    protected void setCurrentRequest( CurrentRequest newCurrentRequest )
    {
        CurrentRequest oldCurrentRequest = this.currentRequest;
        this.currentRequest = newCurrentRequest;
        firePropertyChange( PROP_CURRENTREQUEST, oldCurrentRequest, newCurrentRequest );
    }

    @Deprecated
    /**
     * This method will be removed in future version. Use the
     * propertyChangeSupport instead.
     */
    public void addCurrentWsdlChangeObserver( WsdlChangeObserver o )
    {
        wsdlChangeObserver.add( o );
    }

    @Deprecated
    /**
     * This method will be removed in future version. Use the
     * propertyChangeSupport instead.
     */
    public void removeCurrentWsdlChangeObserver( WsdlChangeObserver o )
    {
        wsdlChangeObserver.remove( o );
    }

    @Deprecated
    /**
     * This method will be removed in future version. Use the
     * propertyChangeSupport instead.
     */
    private void notifyCurrentWsdlChangeObservers()
    {
        for ( WsdlChangeObserver o : wsdlChangeObserver )
        {
            o.wsdlChanged( this );
        }
    }
}
