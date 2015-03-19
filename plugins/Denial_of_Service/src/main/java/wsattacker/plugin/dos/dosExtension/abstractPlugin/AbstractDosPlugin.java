/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.abstractPlugin;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginFunctionInterface;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionLimitedInteger;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.plugin.dos.dosExtension.function.postanalyze.DOSPostAnalyzeFunction;
import wsattacker.plugin.dos.dosExtension.mvc.AttackMVC;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;
import wsattacker.plugin.dos.dosExtension.option.OptionTextAreaSoapMessage;
import wsattacker.plugin.dos.dosExtension.option.OptionTextAreaSoapMessage.PayloadPosition;
import wsattacker.plugin.dos.dosExtension.requestSender.RequestObject;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.support.types.StringToStringsMap;

/**
 * Abstract Plugin for DOS-Attacks!
 */
public abstract class AbstractDosPlugin
    extends AbstractPlugin
{

    public static final String PROP_COUNTERMEASURES = "countermeasures";

    public static final String PROP_OPTIONNUMBERTHREADS = "optionNumberThreads";

    public static final String PROP_OPTIONNUMBERREQUESTS = "optionNumberRequests";

    public static final String PROP_OPTIONSECONDSBETWEENPROBES = "optionSecondsBetweenProbes";

    public static final String PROP_OPTIONSECONDSBETWEENREQUESTS = "optionSecondsBetweenRequests";

    public static final String PROP_OPTIONAUTOFINALIZESWITCH = "optionAutoFinalizeSwitch";

    public static final String PROP_OPTIONAUTOFINALIZESECONDS = "optionAutoFinalizeSeconds";

    public static final String PROP_OPTIONNETWORKTESTENABLED = "optionNetworkTestEnabled";

    public static final String PROP_OPTIONNETWORKTESTNUMBERREQUESTS = "optionNetworkTestNumberRequests";

    public static final String PROP_OPTIONNETWORKTESTREQUESTINTERVAL = "optionNetworkTestRequestInterval";

    public static final String PROP_OPTIONTEXTAREASOAPMESSAGE = "optionTextAreaSoapMessage";

    public static final String PROP_ORIGINALREQUESTRESPONSEPAIR = "originalRequestResponsePair";

    public static final String PROP_ORIGINALREQUESTHEADERFIELDS = "originalRequestHeaderFields";

    public static final String PROP_UNTAMPEREDREQUESTOBJECT = "untamperedRequestObject";

    public static final String PROP_TAMPEREDREQUESTOBJECT = "tamperedRequestObject";

    public static final String PROP_ATTACKMODEL = "attackModel";

    public static final String PROP_ATTACKPRECHECK = "attackPrecheck";

    public static final String NUMBER_OF_PARALLEL_THREADS = "Number of parallel threads";

    public static final String NUMBER_OF_REQUESTS_PER_THREAD = "Number of requests per thread";

    public static final String DELAY_BETWEEN_ATTACK_REQUESTS = "Delay between attack requests";

    public static final String DELAY_BETWEEN_CONTINUOUS_TESTPROBE_REQUES =
        "Delay between continuous testprobe requests";

    public static final String SERVER_RECOVERY_TIME = "Server recovery time";

    public static final String AUTO_STOP = "Auto stop";

    public static final String AUTO_STOP_TIME = "Auto stop: Time";

    public static final String NETWORK_STABILITY_TEST = "Network stability test";

    public static final String NETWORK_STABILITY_TEST_NUMBER_OF_REQUESTS = "Network stability test: Number of requests";

    public static final String NETWORK_STABILITY_TEST_DELAY_BETWEEN_TEST =
        "Network stability test: Delay between testrequest";

    public static final String MESSAGE = "Message";

    private static final long serialVersionUID = 1L;

    // DoS Plugin Options - Default
    private AbstractOptionInteger optionNumberThreads;

    private AbstractOptionInteger optionNumberRequests;

    private AbstractOptionInteger optionSecondsBetweenProbes;

    private AbstractOptionInteger optionSecondsBetweenRequests;

    private AbstractOptionInteger optionSecondsServerLoadRecovery;

    private OptionSimpleBoolean optionAutoFinalizeSwitch;

    private AbstractOptionInteger optionAutoFinalizeSeconds;

    private OptionSimpleBoolean optionNetworkTestEnabled;

    private AbstractOptionInteger optionNetworkTestNumberRequests;

    private AbstractOptionInteger optionNetworkTestRequestInterval;

    private OptionTextAreaSoapMessage optionTextAreaSoapMessage;

    // Requests
    private RequestResponsePair originalRequestResponsePair;

    private Map<String, String> originalRequestHeaderFields;

    private RequestObject untamperedRequestObject;

    private RequestObject tamperedRequestObject;

    // DOS-attackModel
    private AttackModel attackModel;

    private boolean attackPrecheck = true; // Only if true GUI is started!

    private String countermeasures = "";

    /**
     * Get the countermeasures
     * 
     * @return the value of countermeasures
     */
    public String getCountermeasures()
    {
        return countermeasures;
    }

    /**
     * Set the countermeasures
     * 
     * @param countermeasures new value of countermeasures
     */
    public void setCountermeasures( String countermeasures )
    {
        String oldCountermeasures = this.countermeasures;
        this.countermeasures = countermeasures;
        firePropertyChange( PROP_COUNTERMEASURES, oldCountermeasures, countermeasures );
    }

    /**
     * Checks if attack is possible with given original request
     */
    public boolean attackPrecheck()
    {
        return true;
    }

    @Override
    public void initializePlugin()
    {
        // PreInit Plugin
        preInitPlugin();

        // Custom user options added from attack class developer
        initializeDosPlugin();

        // Post Init
        postInitPlugin();
    }

    // Mandatory Init operations for DoS extesnion- Do NOT change!
    public void preInitPlugin()
    {
        setCategory( new String[] { "Denial of Service" } );
        setAuthor( "Andreas Falkenberg" );
        setVersion( "1.1 / 2013-07-26" );
        // DOS Options - MANDATORY FOR DOS-PLUGIN TO WORK
        setOptionNumberThreads( new OptionLimitedInteger( NUMBER_OF_PARALLEL_THREADS, 2,
                                                          "The number of used threads for attacking the web service",
                                                          0, 65536 ) );
        setOptionNumberRequests( new OptionLimitedInteger( NUMBER_OF_REQUESTS_PER_THREAD, 4,
                                                           "The total number of requests sent by each thread", 0, 65536 ) );
        setOptionSecondsBetweenRequests( new OptionLimitedInteger( DELAY_BETWEEN_ATTACK_REQUESTS, 750,
                                                                   "Milliseconds to wait between every attack request",
                                                                   0, 65536 ) );
        setOptionSecondsBetweenProbes( new OptionLimitedInteger(
                                                                 DELAY_BETWEEN_CONTINUOUS_TESTPROBE_REQUES,
                                                                 500,
                                                                 "Milliseconds to wait between every testprobe request (Simulates normal User)",
                                                                 0, 65536 ) );
        setOptionSecondsServerLoadRecovery( new OptionLimitedInteger(
                                                                      SERVER_RECOVERY_TIME,
                                                                      4,
                                                                      "Seconds between receiving last untampered request and sending first untampered request",
                                                                      0, 65536 ) );
        setOptionAutoFinalizeSwitch( new OptionSimpleBoolean( AUTO_STOP, true,
                                                              "false = manuel stop, true = auto stop after defined sec after last tampered request" ) );
        setOptionAutoFinalizeSeconds( new OptionLimitedInteger(
                                                                AUTO_STOP_TIME,
                                                                5,
                                                                "Seconds between receiving last tampered request and finalization (end) of attack",
                                                                0, 655360 ) );
        setOptionNetworkTestEnabled( new OptionSimpleBoolean( NETWORK_STABILITY_TEST, false,
                                                              "false = network stability test disabled, true = enabled" ) );
        setOptionNetworkTestNumberRequests( new OptionLimitedInteger(
                                                                      NETWORK_STABILITY_TEST_NUMBER_OF_REQUESTS,
                                                                      40,
                                                                      "Perform network stability test with defined number of requests",
                                                                      0, 655360 ) );
        setOptionNetworkTestRequestInterval( new OptionLimitedInteger(
                                                                       NETWORK_STABILITY_TEST_DELAY_BETWEEN_TEST,
                                                                       500,
                                                                       "Milliseconds to wait between each Network Stability Testrequest",
                                                                       0, 655360 ) );
        getPluginOptions().add( getOptionNumberThreads() );
        getPluginOptions().add( getOptionNumberRequests() );
        getPluginOptions().add( getOptionSecondsBetweenProbes() );
        getPluginOptions().add( getOptionSecondsBetweenRequests() );
        getPluginOptions().add( getOptionSecondsServerLoadRecovery() );
        getPluginOptions().add( getOptionAutoFinalizeSwitch() );
        getPluginOptions().add( getOptionAutoFinalizeSeconds() );
        getPluginOptions().add( getOptionNetworkTestEnabled() );
        getPluginOptions().add( getOptionNetworkTestNumberRequests() );
        getPluginOptions().add( getOptionNetworkTestRequestInterval() );

        // Plugin Specific Options
        setState( PluginState.Ready );
        setPluginFunctions( new PluginFunctionInterface[] { new DOSPostAnalyzeFunction() } );
    }

    /*
     * Mandatory Init operations for DoS extension In Order to insert a payload placeholer overwrite this method ans
     * insert value of enum PayloadPosition.
     */
    public void postInitPlugin()
    {
        // set payload position -> Always last option
        setOptionTextAreaSoapMessage( new OptionTextAreaSoapMessage( MESSAGE, "set position of payload placeholder",
                                                                     getPayloadPosition() ) );
        getPluginOptions().add( getOptionTextAreaSoapMessage() );
    }

    /**
     * Initialization of DoS attack plugin by user
     */
    public abstract void initializeDosPlugin();

    /*
     * Get default payload position that will get inserted in original SOAP message from SOAP test request
     */
    public abstract PayloadPosition getPayloadPosition();

    /**
     * Creates the final tampered (attack) request with payload
     */
    public abstract void createTamperedRequest();

    /*
     * Creates the final untampered request Might get overwritten in special attack scenarious
     */
    public void createUntamperedRequest()
    {
        // Create clone of original Header
        Map<String, String> httpHeaderMap = new HashMap<String, String>();
        for ( Map.Entry<String, String> entry : getOriginalRequestHeaderFields().entrySet() )
        {
            httpHeaderMap.put( entry.getKey(), entry.getValue() );
        }
        // create Object
        this.setUntamperedRequestObject( httpHeaderMap, originalRequestResponsePair.getWsdlRequest().getEndpoint(),
                                         originalRequestResponsePair.getWsdlRequest().getRequestContent() );
    }

    /**
     * Create Request Padding via appended long comment Depending on size tampered OR untampered request is padded to
     * size of other This way tampered and untampered Request always have same size and are guranteed to cause same
     * network load
     */
    public void createRequestPadding()
    {

        long sizeTamperedRequest = this.tamperedRequestObject.getXmlMessageLength();
        long sizeUntamperedRequest = this.untamperedRequestObject.getXmlMessageLength();
        long sizeDelta = sizeTamperedRequest - sizeUntamperedRequest;

        if ( sizeDelta > 0 )
        {
            // padding for untampered request
            String xmlMessage = this.untamperedRequestObject.getXmlMessage();

            String string = createPadding( sizeDelta, xmlMessage );
            this.untamperedRequestObject.setXmlMessage( string );
        }
        else if ( sizeDelta < 0 )
        {
            // padding for tampered request
            String xmlMessage = this.tamperedRequestObject.getXmlMessage();

            String string = createPadding( Math.abs( sizeDelta ), xmlMessage );
            this.tamperedRequestObject.setXmlMessage( string );
        }
    }

    private String createPadding( long sizeDelta, String xmlMessage )
    {
        StringBuilder sb = new StringBuilder();

        String comment_start = "<!--";
        String comment_end = "-->";
        int offset = comment_start.length() + comment_end.length();

        int l = (int) sizeDelta - offset;

        sb.append( comment_start );

        for ( int i = 0; i < l; i++ )
        {
            sb.append( "c" );
        }

        sb.append( comment_end );
        sb.append( xmlMessage );

        String string = sb.toString();
        return string;
    }

    /**
     * get Original Request Headers Method actually sends request and reads header fields
     */
    public void createOriginalRequestHeaderFields()
    {
        Map<String, String> httpHeaderMap = new HashMap<String, String>();

        StringToStringsMap originalHeaders = originalRequestResponsePair.getWsdlResponse().getRequestHeaders();// response.getRequestHeaders();
        for ( Map.Entry<String, List<String>> entry : originalHeaders.entrySet() )
        {
            for ( String value : entry.getValue() )
            {
                httpHeaderMap.put( entry.getKey(), value );
            }
        }

        this.setOriginalRequestHeaderFields( httpHeaderMap );
    }

    /*
     * Performs the actual attack. No need to override!
     * @param original
     */
    @Override
    public void attackImplementationHook( RequestResponsePair original )
    {

        // save OriginalRequestResponsePair pointer
        setOriginalRequestResponsePair( original );

        // save Original Header Fields for all subsequent requests
        createOriginalRequestHeaderFields();

        // check if attack is feasable with given original SOAP message
        if ( attackPrecheck() )
        {

            // create the tampered and untampered request
            createTamperedRequest();
            createUntamperedRequest();

            // create Request Padding
            createRequestPadding();

            // perform DOS Attack
            // - returns ONLY if attackModel is in finished state!
            setAttackModel( AttackMVC.runDosAttack( this ) );

            // Set Attack Points
            setCurrentPoints( attackModel.getWsAttackerPoints() );

            // Set Plugin State
            if ( getCurrentPoints() == 0 )
            {
                info( attackModel.getWsAttackerResults() );
                setState( PluginState.Failed );
            }
            else if ( getCurrentPoints() > 0 )
            {
                important( attackModel.getWsAttackerResults() );
                setState( PluginState.Finished );
            }
        }
        else
        {
            setCurrentPoints( 0 );
            important( "Attack not possible - Structure of SOAP Message is not suitable!" );
            setState( PluginState.Failed );
        }
    }

    @Override
    public void clean()
    {
        setAttackModel( null );
        setCurrentPoints( 0 );
        setState( PluginState.Ready );

        // clean functionList with empty model!
        if ( getPluginFunctions( 0 ) instanceof DOSPostAnalyzeFunction )
        {
            DOSPostAnalyzeFunction b = (DOSPostAnalyzeFunction) getPluginFunctions( 0 );
            b.setAttackModel( attackModel );
        }
    }

    @Override
    public void stopHook()
    {
        // restore possible data corruption
        // if (originalAction != null && originalRequest != null &&
        // !originalRequest.getOperation().getAction().equals(originalAction)) {
        // originalRequest.getOperation().setAction(originalAction);
        // originalRequest = null;
        // originalAction = null;
        // }
        setTamperedRequestObject( null );
        setUntamperedRequestObject( null );
    }

    @Override
    public boolean wasSuccessful()
    {
        // successfull only server is vulnerable for one method
        // note: one point = possible server misconfiguration
        return isFinished() && ( getCurrentPoints() > 1 );
    }

    @Override
    public void restoreConfiguration( AbstractPlugin plugin )
    {
        /*
         * if (plugin instanceof CoersiveParsing) { CoersiveParsing old = (CoersiveParsing) plugin; // restore
         * pluginOptions // ... }
         */
    }

    /**
     * ------------------------------------------ Getter and Setter ------------------------------------------
     */
    public AbstractOptionInteger getOptionNumberThreads()
    {
        return optionNumberThreads;
    }

    public AbstractOptionInteger getOptionNumberRequests()
    {
        return optionNumberRequests;
    }

    public AbstractOptionInteger getOptionSecondsBetweenProbes()
    {
        return optionSecondsBetweenProbes;
    }

    public AbstractOptionInteger getOptionSecondsBetweenRequests()
    {
        return optionSecondsBetweenRequests;
    }

    public AbstractOptionInteger getOptionSecondsServerLoadRecovery()
    {
        return optionSecondsServerLoadRecovery;
    }

    public void setOptionSecondsServerLoadRecovery( AbstractOptionInteger optionSecondsServerLoadRecovery )
    {
        this.optionSecondsServerLoadRecovery = optionSecondsServerLoadRecovery;
    }

    public WsdlRequest getOriginalRequest()
    {
        return originalRequestResponsePair.getWsdlRequest();
    }

    public String getOriginalAction()
    {
        return originalRequestResponsePair.getWsdlRequest().getAction();
    }

    public AttackModel getAttackModel()
    {
        return attackModel;
    }

    public boolean getAttackPrecheck()
    {
        return attackPrecheck;
    }

    public OptionSimpleBoolean getOptionAutoFinalizeSwitch()
    {
        return optionAutoFinalizeSwitch;
    }

    public AbstractOptionInteger getOptionAutoFinalizeSeconds()
    {
        return optionAutoFinalizeSeconds;
    }

    public OptionSimpleBoolean getOptionNetworkTestEnabled()
    {
        return optionNetworkTestEnabled;
    }

    public AbstractOptionInteger getOptionNetworkTestNumberRequests()
    {
        return optionNetworkTestNumberRequests;
    }

    public AbstractOptionInteger getOptionNetworkTestRequestInterval()
    {
        return optionNetworkTestRequestInterval;
    }

    public RequestObject getTamperedRequestObject()
    {
        return tamperedRequestObject;
    }

    public void setTamperedRequestObject( Map<String, String> httpHeaderMap, String endpoint, String msg )
    {
        this.setTamperedRequestObject( new RequestObject( msg, endpoint, httpHeaderMap ) );
    }

    public RequestObject getUntamperedRequestObject()
    {
        return untamperedRequestObject;
    }

    public void setUntamperedRequestObject( Map<String, String> httpHeaderMap, String endpoint, String msg )
    {
        this.setUntamperedRequestObject( new RequestObject( msg, endpoint, httpHeaderMap ) );
    }

    public OptionTextAreaSoapMessage getOptionTextAreaSoapMessage()
    {
        return optionTextAreaSoapMessage;
    }

    public Map<String, String> getOriginalRequestHeaderFields()
    {
        if ( originalRequestHeaderFields == null )
        {
            setOriginalRequestHeaderFields( new HashMap<String, String>() );
        }
        return originalRequestHeaderFields;
    }

    public RequestResponsePair getOriginalRequestResponsePair()
    {
        return originalRequestResponsePair;
    }

    public void setOptionNumberThreads( AbstractOptionInteger optionNumberThreads )
    {
        wsattacker.main.composition.plugin.option.AbstractOptionInteger oldOptionNumberThreads =
            this.optionNumberThreads;
        this.optionNumberThreads = optionNumberThreads;
        firePropertyChange( PROP_OPTIONNUMBERTHREADS, oldOptionNumberThreads, optionNumberThreads );
    }

    public void setOptionNumberRequests( AbstractOptionInteger optionNumberRequests )
    {
        wsattacker.main.composition.plugin.option.AbstractOptionInteger oldOptionNumberRequests =
            this.optionNumberRequests;
        this.optionNumberRequests = optionNumberRequests;
        firePropertyChange( PROP_OPTIONNUMBERREQUESTS, oldOptionNumberRequests, optionNumberRequests );
    }

    public void setOptionSecondsBetweenProbes( AbstractOptionInteger optionSecondsBetweenProbes )
    {
        wsattacker.main.composition.plugin.option.AbstractOptionInteger oldOptionSecondsBetweenProbes =
            this.optionSecondsBetweenProbes;
        this.optionSecondsBetweenProbes = optionSecondsBetweenProbes;
        firePropertyChange( PROP_OPTIONSECONDSBETWEENPROBES, oldOptionSecondsBetweenProbes, optionSecondsBetweenProbes );
    }

    public void setOptionSecondsBetweenRequests( AbstractOptionInteger optionSecondsBetweenRequests )
    {
        wsattacker.main.composition.plugin.option.AbstractOptionInteger oldOptionSecondsBetweenRequests =
            this.optionSecondsBetweenRequests;
        this.optionSecondsBetweenRequests = optionSecondsBetweenRequests;
        firePropertyChange( PROP_OPTIONSECONDSBETWEENREQUESTS, oldOptionSecondsBetweenRequests,
                            optionSecondsBetweenRequests );
    }

    public void setOptionAutoFinalizeSwitch( OptionSimpleBoolean optionAutoFinalizeSwitch )
    {
        wsattacker.main.plugin.option.OptionSimpleBoolean oldOptionAutoFinalizeSwitch = this.optionAutoFinalizeSwitch;
        this.optionAutoFinalizeSwitch = optionAutoFinalizeSwitch;
        firePropertyChange( PROP_OPTIONAUTOFINALIZESWITCH, oldOptionAutoFinalizeSwitch, optionAutoFinalizeSwitch );
    }

    public void setOptionAutoFinalizeSeconds( AbstractOptionInteger optionAutoFinalizeSeconds )
    {
        wsattacker.main.composition.plugin.option.AbstractOptionInteger oldOptionAutoFinalizeSeconds =
            this.optionAutoFinalizeSeconds;
        this.optionAutoFinalizeSeconds = optionAutoFinalizeSeconds;
        firePropertyChange( PROP_OPTIONAUTOFINALIZESECONDS, oldOptionAutoFinalizeSeconds, optionAutoFinalizeSeconds );
    }

    public void setOptionNetworkTestEnabled( OptionSimpleBoolean optionNetworkTestEnabled )
    {
        wsattacker.main.plugin.option.OptionSimpleBoolean oldOptionNetworkTestEnabled = this.optionNetworkTestEnabled;
        this.optionNetworkTestEnabled = optionNetworkTestEnabled;
        firePropertyChange( PROP_OPTIONNETWORKTESTENABLED, oldOptionNetworkTestEnabled, optionNetworkTestEnabled );
    }

    public void setOptionNetworkTestNumberRequests( AbstractOptionInteger optionNetworkTestNumberRequests )
    {
        wsattacker.main.composition.plugin.option.AbstractOptionInteger oldOptionNetworkTestNumberRequests =
            this.optionNetworkTestNumberRequests;
        this.optionNetworkTestNumberRequests = optionNetworkTestNumberRequests;
        firePropertyChange( PROP_OPTIONNETWORKTESTNUMBERREQUESTS, oldOptionNetworkTestNumberRequests,
                            optionNetworkTestNumberRequests );
    }

    public void setOptionNetworkTestRequestInterval( AbstractOptionInteger optionNetworkTestRequestInterval )
    {
        wsattacker.main.composition.plugin.option.AbstractOptionInteger oldOptionNetworkTestRequestInterval =
            this.optionNetworkTestRequestInterval;
        this.optionNetworkTestRequestInterval = optionNetworkTestRequestInterval;
        firePropertyChange( PROP_OPTIONNETWORKTESTREQUESTINTERVAL, oldOptionNetworkTestRequestInterval,
                            optionNetworkTestRequestInterval );
    }

    public void setOptionTextAreaSoapMessage( OptionTextAreaSoapMessage optionTextAreaSoapMessage )
    {
        wsattacker.plugin.dos.dosExtension.option.OptionTextAreaSoapMessage oldOptionTextAreaSoapMessage =
            this.optionTextAreaSoapMessage;
        this.optionTextAreaSoapMessage = optionTextAreaSoapMessage;
        firePropertyChange( PROP_OPTIONTEXTAREASOAPMESSAGE, oldOptionTextAreaSoapMessage, optionTextAreaSoapMessage );
    }

    public void setOriginalRequestResponsePair( RequestResponsePair originalRequestResponsePair )
    {
        wsattacker.main.composition.testsuite.RequestResponsePair oldOriginalRequestResponsePair =
            this.originalRequestResponsePair;
        this.originalRequestResponsePair = originalRequestResponsePair;
        firePropertyChange( PROP_ORIGINALREQUESTRESPONSEPAIR, oldOriginalRequestResponsePair,
                            originalRequestResponsePair );
    }

    public void setOriginalRequestHeaderFields( Map<String, String> originalRequestHeaderFields )
    {
        java.util.Map<java.lang.String, java.lang.String> oldOriginalRequestHeaderFields =
            this.originalRequestHeaderFields;
        this.originalRequestHeaderFields = originalRequestHeaderFields;
        firePropertyChange( PROP_ORIGINALREQUESTHEADERFIELDS, oldOriginalRequestHeaderFields,
                            originalRequestHeaderFields );
    }

    public void setUntamperedRequestObject( RequestObject untamperedRequestObject )
    {
        wsattacker.plugin.dos.dosExtension.requestSender.RequestObject oldUntamperedRequestObject =
            this.untamperedRequestObject;
        this.untamperedRequestObject = untamperedRequestObject;
        firePropertyChange( PROP_UNTAMPEREDREQUESTOBJECT, oldUntamperedRequestObject, untamperedRequestObject );
    }

    public void setTamperedRequestObject( RequestObject tamperedRequestObject )
    {
        wsattacker.plugin.dos.dosExtension.requestSender.RequestObject oldTamperedRequestObject =
            this.tamperedRequestObject;
        this.tamperedRequestObject = tamperedRequestObject;
        firePropertyChange( PROP_TAMPEREDREQUESTOBJECT, oldTamperedRequestObject, tamperedRequestObject );
    }

    public void setAttackModel( AttackModel attackModel )
    {
        wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel oldAttackModel = this.attackModel;
        this.attackModel = attackModel;
        firePropertyChange( PROP_ATTACKMODEL, oldAttackModel, attackModel );
    }

    public void setAttackPrecheck( boolean attackPrecheck )
    {
        boolean oldAttackPrecheck = this.attackPrecheck;
        this.attackPrecheck = attackPrecheck;
        firePropertyChange( PROP_ATTACKPRECHECK, oldAttackPrecheck, attackPrecheck );
    }
}
