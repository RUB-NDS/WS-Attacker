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
package wsattacker.gui;

import com.eviware.soapui.DefaultSoapUICore;
import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.model.iface.Request.SubmitException;
import com.eviware.soapui.support.SoapUIException;
import java.io.File;
import java.io.IOException;
import java.util.Iterator;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import wsattacker.gui.component.log.GuiAppender;
import wsattacker.gui.component.target.WsdlLoaderGUI_NB;
import wsattacker.main.Preferences;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.plugin.PluginManager;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.testsuite.CurrentRequest;
import wsattacker.main.testsuite.TestSuite;

public class GuiController
    implements ControllerInterface
{

    private static final GuiController c = new GuiController(); // singleton

    PluginManager pluginManager;

    TestSuite testSuite;

    Preferences prefs;

    Logger LOG = Logger.getLogger( GuiController.class );

    GuiView guiView;

    private boolean abortAttacks;

    Thread runThread;

    PluginRunner runner;

    // singleton
    private GuiController()
    {

        abortAttacks = false;
        // get allPlugins
        this.pluginManager = PluginManager.getInstance();
        reloadPlugins();

        // create a new test suite
        this.testSuite = TestSuite.getInstance();

        // preferences
        this.prefs = Preferences.getInstance();

        // no thread
        this.runThread = new Thread();

        // create gui
        this.guiView = new GuiView( this );

        Thread viewThread = new Thread( this.guiView );
        viewThread.start();
    }

    // singleton
    public static GuiController getInstance()
    {
        return c;
    }

    // ==============================================
    // Interface Methods:
    // Plugins
    // ==============================================
    @Override
    public PluginManager getPluginManager()
    {
        // return this.allPlugins.getPlugins();
        return this.pluginManager;
    }

    @Override
    public void reloadPlugins()
    {
        LOG.info( "Adding Libraries from \"lib\" folder" );
        getPluginManager().loadAvailablePlugins( new File( "lib" ) );
        LOG.info( "Reloading Plugins" );
        getPluginManager().loadAvailablePlugins( new File( "plugins" ) );
    }

    @Override
    public void setPluginActive( int index, boolean active )
    {
        AbstractPlugin plugin = getPluginManager().getByIndex( index );
        setPluginActive( plugin, active );
    }

    @Override
    public void setPluginActive( String pluginName, boolean active )
    {
        AbstractPlugin plugin = getPluginManager().getByName( pluginName );
        setPluginActive( plugin, active );
    }

    private void setPluginActive( AbstractPlugin plugin, boolean active )
    {
        if ( plugin != null )
        {
            if ( getPluginManager().isActive( plugin ) != active )
            {
                LOG.info( String.format( ( active ? "(+) A" : "(-) Dea" ) + "ctivating Plugin %s", plugin.getName() ) );
                getPluginManager().setActive( plugin, active );
            }
        }
        else
        {
            LOG.warn( String.format( "(!) Could not activate Plugin" ) );
        }
    }

    @Override
    public void setAllPluginActive( boolean active )
    {
        LOG.info( ( active ? "(+) A" : "(-) Dea" ) + "ctivating all Plugins" );
        getPluginManager().setAllActive( active );
    }

    @Override
    public void setOptionValue( AbstractPlugin plugin, String optionName, String optionValue )
    {
        AbstractOption option = plugin.getPluginOptions().getByName( optionName );
        if ( option == null )
        {
            throw new NullPointerException( "Option is null" );
        }
        if ( option.isValid( optionValue ) )
        {
            LOG.debug( String.format( "Set PluginOption for '%s': {%s=%s}", plugin.getName(), optionName, optionValue ) );
            option.parseValue( optionValue );
        }
        LOG.debug( String.format( "Value {%s=%s} for Plugin '%s' is INVALID!", optionName, optionValue,
                                  plugin.getName() ) );
    }

    @Override
    public void startActivePlugins()
    {
        if ( runThread.isAlive() )
        {
            LOG.fatal( "You can't start Attacks. Another process is running." );
            return;
        }
        runner = new PluginRunner( testSuite );
        runThread = new Thread( runner );
        runThread.setName( "Run Plugins" );
        guiView.getAttackOverview().enableStartButton( false );
        guiView.getAttackOverview().enableStopButton( true );
        guiView.getAttackOverview().enableCleanButton( false );
        guiView.getAttackOverview().enableSaveButton( false );
        // SoapUI.getThreadPool().execute(runThread);
        runThread.start();
    }

    public void stopActivePlugins()
    {
        Thread stopThread = new Thread( new PluginStopper() );
        stopThread.run();
        runThread.setName( "Run Plugins" );
    }

    class PluginStopper
        implements Runnable
    {

        @SuppressWarnings( "deprecation" )
        @Override
        public void run()
        {
            if ( runThread.isAlive() && runThread.getName().equals( "Run Plugins" ) )
            {
                abortAttacks = true;
                LOG.info( "Stopping all active plugins" );
                AbstractPlugin active = runner.getActive();
                LOG.warn( "Gently aborting plugin '" + active.getName() + "' (Waiting for 3 sec)" );
                active.abortAttack();
                try
                {
                    Thread.sleep( 3000 );
                }
                catch ( InterruptedException e )
                {
                } // wait for 3 seconds
                  // know force to kill the thread if its still running.
                if ( runThread.isAlive() && runThread.getName().equals( "Run Plugins" ) )
                {
                    LOG.warn( "Force to kill thread, since plugin is still running." );
                    runThread.stop();
                }
                active.stopAttack();
                Iterator<AbstractPlugin> it = getPluginManager().getActivePluginIterator();
                while ( it.hasNext() )
                {
                    AbstractPlugin otherPlugin = it.next();
                    if ( otherPlugin.isReady() )
                    {
                        otherPlugin.stopAttack();
                    }
                }
                setEnabledTabs( true, 0, 1, 2 );
                abortAttacks = false;
            }
            guiView.getAttackOverview().enableStartButton( false );
            guiView.getAttackOverview().enableStopButton( false );
            guiView.getAttackOverview().enableCleanButton( true );
            guiView.getAttackOverview().enableSaveButton( true );
        }
    }

    @Override
    public void cleanPlugins()
    {
        boolean noError = true;
        Iterator<AbstractPlugin> it = getPluginManager().iterator();
        AbstractPlugin plugin;
        while ( it.hasNext() )
        {
            plugin = it.next();
            plugin.clean();
            if ( plugin.isFinished() || plugin.isRunning() )
            {
                LOG.error( "Plugin " + plugin.getName() + " could not be cleaned, Status is still " + plugin.getState() );
                noError |= false;
            }
            if ( plugin.getCurrentPoints() != 0 )
            {
                LOG.error( "Plugin " + plugin.getName() + "could not be cleaned, it has still "
                    + plugin.getCurrentPoints() + " Points" );
                noError |= false;
            }
        }
        Result.getGlobalResult().clear();
        if ( noError )
        {
            LOG.info( "All Plugins successfully cleaned" );
        }
        guiView.getAttackOverview().enableStartButton( true );
        guiView.getAttackOverview().enableStopButton( false );
        guiView.getAttackOverview().enableCleanButton( false );
        guiView.getAttackOverview().enableSaveButton( false );
    }

    class PluginRunner
        implements Runnable
    {

        TestSuite testSuite;

        AbstractPlugin active;

        public PluginRunner( TestSuite testSuite )
        {
            this.testSuite = testSuite;
            this.active = null;
        }

        public void run()
        {
            AbstractPlugin plugin;
            Iterator<AbstractPlugin> it;
            // Check if everything is allright
            if ( testSuite.getCurrentRequest().getWsdlRequest() == null )
            {
                LOG.warn( "You have to load a WSDL first" );
                return;
            }
            if ( testSuite.getCurrentRequest().getWsdlResponse() == null )
            {
                LOG.warn( "You must submit a test request first." );
                return;
            }
            if ( getPluginManager().countActivePlugins() < 1 )
            {
                LOG.warn( "You must enable at least one Plugin" );
                return;
            }
            it = getPluginManager().getActivePluginIterator();
            while ( it.hasNext() )
            {
                plugin = it.next();
                if ( !plugin.isReady() )
                {
                    LOG.warn( "Not all Plugins are Ready" );
                    return;
                }
            }
            // start attack
            LOG.info( "Starting all active Plugins..." );
            setEnabledTabs( false, 0, 1, 2 );
            it = getPluginManager().getActivePluginIterator();
            while ( it.hasNext() && !abortAttacks )
            {
                plugin = it.next();
                active = plugin;
                LOG.info( "Starting plugin '" + plugin.getName() + "'" );
                plugin.startAttack();
                LOG.info( "Plugin finished: " + plugin.getCurrentPoints() + "/" + plugin.getMaxPoints() );
            }
            active = null;
            setEnabledTabs( true, 0, 1, 2 );
            guiView.getAttackOverview().enableStartButton( false );
            guiView.getAttackOverview().enableStopButton( false );
            guiView.getAttackOverview().enableCleanButton( true );
            guiView.getAttackOverview().enableSaveButton( true );
        }

        public AbstractPlugin getActive()
        {
            return active;
        }
    }

    @Override
    public void savePluginConfiguration( File file )
    {
        try
        {
            getPluginManager().savePlugins( file );
        }
        catch ( IOException e )
        {
            LOG.error( "IO Exception : " + e.getMessage() );
        }
        catch ( Exception e )
        {
            LOG.error( "Unknown Error:" + e.getMessage() );
        }
    }

    @Override
    public void loadPluginConfiguration( File file )
    {
        try
        {
            getPluginManager().loadPlugins( file );
        }
        catch ( IOException e )
        {
            LOG.error( "IO Exception : " + e.getMessage() );
        }
        catch ( ClassNotFoundException e )
        {
            LOG.error( "Could not find all Plugin Classes" );
        }
        catch ( Exception e )
        {
            LOG.error( "Unknown Error:" + e.getMessage() );
        }
        LOG.info( "Successfully loaded Configuration" );
    }

    // ==============================================
    // Interface Methods:
    // WsdlProject
    // ==============================================
    @Override
    public TestSuite getTestSuite()
    {
        return this.testSuite;
    }

    @Override
    public void setWsdl( String uri )
    {
        if ( runThread.isAlive() )
        {
            LOG.fatal( "You can't start Attacks. Another process is running." );
            return;
        }
        LOG.info( "Trying to load WSDL from '" + uri + "'" );
        Runnable runner = new WsdlLoadRunner( uri );
        runThread = new Thread( runner );
        runThread.setName( "Load WSDL" );
        runThread.start();
        // SoapUI.getThreadPool().execute(runThread);
    }

    class WsdlLoadRunner
        implements Runnable
    {

        String uri;

        public WsdlLoadRunner( String uri )
        {
            this.uri = uri;
        }

        @Override
        public void run()
        {
            WsdlLoaderGUI_NB wsdlGui = guiView.getWsdlLoader();

            // disable fields
            wsdlGui.getUriField().setEnabled( false );
            wsdlGui.getLoadButton().setEnabled( false );
            wsdlGui.getServiceComboBox().setEnabled( false );
            wsdlGui.getOperationComboBox().setEnabled( false );
            wsdlGui.getNewRequestButtom().setEnabled( false );
            wsdlGui.updateUI();

            try
            {
                testSuite.loadWsdl( uri );
                // re-enable fields
                wsdlGui.getServiceComboBox().setEnabled( true );
                wsdlGui.getOperationComboBox().setEnabled( true );
                wsdlGui.getNewRequestButtom().setEnabled( true );
            }
            catch ( SoapUIException e )
            {
                LOG.error( "SoapUIException while loading WSDL: " + e.getMessage() );
            }
            catch ( UnsupportedOperationException e )
            {
                LOG.error( "UnsupportedOperationException while loading WSDL: " + e.getMessage() );
            }
            catch ( Exception e )
            {
                LOG.error( "Wsdl File could not be loaded: " + e.getMessage() );
            }
            finally
            {
                // re-enable fields
                wsdlGui.getUriField().setEnabled( true );
                wsdlGui.getLoadButton().setEnabled( true );
            }
        }
    }

    @Override
    public boolean setCurrentService( String serviceName )
    {
        WsdlProject project = testSuite.getProject();
        if ( ( project != null ) && ( project.getInterfaceByName( serviceName ) != null ) )
        {
            WsdlInterface service = (WsdlInterface) project.getInterfaceByName( serviceName );
            setCurrentService( service );
            return true;
        }
        else
        {
            LOG.warn( "No such service available" );
            return false;
        }

    }

    @Override
    public boolean setCurrentService( int index )
    {
        WsdlProject project = testSuite.getProject();
        if ( ( project != null ) && ( index >= 0 ) && ( index < project.getInterfaceCount() ) )
        {
            WsdlInterface service = (WsdlInterface) project.getInterfaceAt( index );
            setCurrentService( service );
            return true;
        }
        else
        {
            LOG.warn( "No such service available" );
            return false;
        }
    }

    private void setCurrentService( WsdlInterface service )
    {
        this.testSuite.getCurrentInterface().setWsdlInterface( service );
        LOG.info( "Set current service to '" + service.getName() + "'" );
    }

    @Override
    public boolean setCurrentOperation( String operationString )
    {
        WsdlOperation operation =
            testSuite.getCurrentInterface().getWsdlInterface().getOperationByName( operationString );
        return setCurrentOperation( operation );
    }

    @Override
    public boolean setCurrentOperation( int index )
    {
        WsdlOperation operation = testSuite.getCurrentInterface().getWsdlInterface().getOperationAt( index );
        return setCurrentOperation( operation );

    }

    private boolean setCurrentOperation( WsdlOperation operation )
    {
        if ( operation == null )
        {
            LOG.warn( "Unset current operatoin (null)" );
            return false;
        }
        this.testSuite.getCurrentOperation().setWsdlOperation( operation );
        LOG.info( "Set current operation to '" + operation.getName() + "'" );
        return true;
    }

    @Override
    public void resetRequestContent()
    {
        WsdlRequest request = testSuite.getCurrentRequest().getWsdlRequest();
        if ( request != null )
        {
            LOG.info( "Resetting content for basic Request" );
            request.setRequestContent( request.getOperation().createRequest( prefs.isCreateOptionalElements() ) );
        }
    }

    @Override
    public void setRequestContent( String content )
    {
        LOG.trace( "Setting request content to:\n" + content );
        WsdlRequest request = testSuite.getCurrentRequest().getWsdlRequest();
        if ( request != null )
        {
            request.setRequestContent( content );
        }
        else
        {
            LOG.warn( "There is no current Request" );
        }
    }

    @Override
    public void doTestRequest()
    {
        if ( runThread.isAlive() )
        {
            LOG.fatal( "You can't do a Test Request. Another process is running." );
        }
        WsdlRequest request = testSuite.getCurrentRequest().getWsdlRequest();
        if ( request == null )
        {
            LOG.warn( "You have to load a WSDL first" );
            return;
        }
        LOG.info( "Doing a Test Request" );
        Runnable runner = new TestRequest( testSuite.getCurrentRequest() );
        runThread = new Thread( runner );
        runThread.setName( "Test Request" );
        runThread.start();
        // SoapUI.getThreadPool().execute(runThread);

    }

    class TestRequest
        implements Runnable
    {

        final CurrentRequest request;

        public TestRequest( CurrentRequest request )
        {
            this.request = request;
        }

        @Override
        public void run()
        {
            LOG.info( "Submitting Request..." );
            try
            {
                request.submitRequest();
            }
            catch ( NullPointerException e )
            {
                String error = "Error while doing Test Request" + e.getMessage();
                LOG.error( error );
                return;
            }
            catch ( SubmitException e )
            {
                String error = "Error while doing Test Request. " + e.getMessage();
                LOG.error( error );
                return;
            }
            catch ( Exception e )
            {
                LOG.error( "Unknown Error:" + e.getMessage() );
                return;
            }
            String responseContent = request.getWsdlResponse().getContentAsString();
            if ( responseContent == null )
            {
                LOG.warn( "Got an empty response. Bad request?" );
            }
            else
            {
                LOG.info( "Successfully received Response" );
            }
        }
    }

    // ==============================================
    // Help Methods:
    // ==============================================
    private void setEnabledTabs( boolean enabled, int... tabindex )
    {
        for ( int i : tabindex )
        {
            guiView.getMainWindows().getTabs().setEnabledAt( i, enabled );
        }
    }

    // Additional Getter
    public GuiView getGuiView()
    {
        return guiView;
    }
}
