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
package wsattacker.plugin.dos.dosExtension.mvc.model;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.apache.commons.math3.stat.descriptive.rank.Median;

import wsattacker.main.plugin.PluginOptionContainer;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.plugin.dos.dosExtension.abstractPlugin.AbstractDosPlugin;
import wsattacker.plugin.dos.dosExtension.attackThreads.PerformAttackThread;
import wsattacker.plugin.dos.dosExtension.clock.Clock;
import wsattacker.plugin.dos.dosExtension.clock.TickerThread;
import wsattacker.plugin.dos.dosExtension.logEntry.LogEntryInterval;
import wsattacker.plugin.dos.dosExtension.logEntry.LogEntryRequest;
import wsattacker.plugin.dos.dosExtension.mvc.view.AttackListener;
import wsattacker.plugin.dos.dosExtension.requestSender.RequestObject;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.submit.transports.http.WsdlResponse;

/**
 * JAVA MVC Model: - used for managing data of attack and keeping state! - data externaly modified only via controller!
 * - views (Gui) are registered listeners of model
 */
public class AttackModel
    implements AttackModelSubject // implements Oberserver
// (DesignPatterns Seite
// 52)
{

    private static final int MAX_POINTS = 100;

    int min, max;

    // Attack Init Vars!
    private int numberRequestsPerThread = 0;

    private int numberThreads = 0;

    private int millisecondsServerLoadRecovery; // s

    private int millisecondsBetweenProbes; // ms

    private int millisecondsBetweenRequests; // ms

    private int intervalLengthReport = 1000;// ms

    private String attackName;

    private String attackDescription;

    private String attackCountermeasures;

    private String wsdlUrl;

    private String ip;

    private String payload;

    // StopWatch Variables
    private Clock clock;

    private TickerThread ticker;

    private String attackTime = "0"; // "0:000";

    // Attack Thread References
    private Thread performAttackThread;

    private Thread sendProbeRequestsThread;

    // WSDL-Response/Request Refernces
    private WsdlRequest wsdlRequestOriginal;

    private WsdlResponse wsdlResponseOriginal;

    private RequestObject tamperedRequestObject;

    private RequestObject untamperedRequestObject;

    private Map<String, String> originalRequestHeaderFields;

    // Model Listener
    private ArrayList<AttackListener> listeners;

    // Attack States
    private final String[] stateArray = { "Attack initialized<br />", "Performing network stability test<br />",
        "Attack running <br />sending untampered requests", "Attack running <br />allowing server to recover",
        "Attack running <br />sending tampered requests", "Attack running <br />ready to finalize",
        "Attack finished<br />", "Attack aborted by user<br />", "Generating results - please wait...<br />",
        "Attack done<br />sending test probes for defined number of seconds" };

    private String currentAttackState = "";

    private boolean attackFinished = false;

    private boolean attackAborted = false;

    // Auto attack completion with/without user intervention
    private boolean autoFinalizeSwitch = false;

    private int autoFinalizeMilliSeconds = 60;

    // Network test
    private boolean networkTestEnabled = false;

    private boolean networkTestFinished = false;

    private int networkTestNumberRequests = 100;

    private int networkTestRequestIntervalInMilliseconds = 333; // ms

    private double networkTestResult = 0.0;

    private String networkTestResultString = "";

    // Attack Progress Counter
    private int counterThreadsUntampered = 0;

    private int counterThreadsTampered = 0;

    private int counterRequestsSendTampered = 0;

    private int counterRequestsSendUntampered = 0;

    private int counterRequestsSendNetworkTest = 0;

    private int counterProbesSend = 0;

    // Attack Bytesize
    private int requestSizeUntampered;

    private int requestSizeTampered;

    private int requestSizeTestProbe;

    private int requestSizePaddedUntampered;

    private int requestSizePaddedTampered;

    // Attack time logging
    private long tsAttackStart; // When did the attack start -> via
                                // startAttack()

    private long tsAttackStop; // When did it end -> via finalizeAttack()

    private long tsUntamperedStart; // via performAttackThread()

    private long tsTamperedStart; // via performAttackThread()

    private long tsTamperedLastSend; // via performAttackThread()

    private List<LogEntryRequest> logList;

    private List<LogEntryRequest> logListUntamperedRequests; // added in each
                                                             // attackthread

    private List<LogEntryRequest> logListTamperedRequests;

    private List<LogEntryRequest> logListTestProbeRequests;

    private List<LogEntryRequest> logListNetworktestRequests;

    // Median Values
    private double medianUntampered;

    private double medianTampered;

    // Attack time Graph-DataArrays
    private Map<Integer, LogEntryInterval> mapLogEntryIntervalUntampered;

    private Map<Integer, LogEntryInterval> mapLogEntryIntervalTampered;

    private Map<Integer, LogEntryInterval> mapLogEntryIntervalTestProbe;

    // Return values for classical WS-Attacker logging
    private String wsAttackerResults = "Attack finished";

    private final int sampleCountAttackEffectivness = 10; // How many samples
                                                          // should we take to
                                                          // calculate
                                                          // attackEffectivness?

    private final int payloadSuccessThreshold = 3; // when is an attack called
                                                   // succesful based on
                                                   // effectivness!

    // Attack options store
    private PluginOptionContainer pluginOptions;

    /**
     * Empty Constructor - used for preInit instantiation!
     */
    public AttackModel()
    {
    }

    /**
     * Constructor
     */
    public AttackModel( AbstractDosPlugin plugin )
    {
        pluginOptions = plugin.getPluginOptions();
        // Read Parameter and Object from actual Plugin
        this.numberRequestsPerThread = plugin.getOptionNumberRequests().getValue();
        this.numberThreads = plugin.getOptionNumberThreads().getValue();
        this.millisecondsServerLoadRecovery = plugin.getOptionSecondsServerLoadRecovery().getValue() * 1000;
        this.millisecondsBetweenProbes = plugin.getOptionSecondsBetweenProbes().getValue();
        this.millisecondsBetweenRequests = plugin.getOptionSecondsBetweenRequests().getValue();
        this.autoFinalizeSwitch = plugin.getOptionAutoFinalizeSwitch().isOn();
        this.autoFinalizeMilliSeconds = plugin.getOptionAutoFinalizeSeconds().getValue() * 1000;
        this.networkTestEnabled = plugin.getOptionNetworkTestEnabled().isOn();
        this.networkTestNumberRequests = plugin.getOptionNetworkTestNumberRequests().getValue();
        this.networkTestRequestIntervalInMilliseconds = plugin.getOptionNetworkTestRequestInterval().getValue();
        this.ip = "0.0.0.0"; // TODO: read out
        this.wsdlUrl = plugin.getOriginalRequestResponsePair().getWsdlRequest().getEndpoint();
        this.attackName = plugin.getName();
        this.attackDescription = plugin.getDescription();
        this.attackCountermeasures = plugin.getCountermeasures();
        this.wsdlRequestOriginal = plugin.getOriginalRequestResponsePair().getWsdlRequest();
        this.wsdlResponseOriginal = plugin.getOriginalRequestResponsePair().getWsdlResponse();
        this.originalRequestHeaderFields = plugin.getOriginalRequestHeaderFields();
        this.tamperedRequestObject = plugin.getTamperedRequestObject();
        this.untamperedRequestObject = plugin.getUntamperedRequestObject();

        // set requestSize
        requestSizeUntampered = untamperedRequestObject.getXmlMessageLength();
        requestSizeTampered = this.tamperedRequestObject.getXmlMessageLength();
        requestSizePaddedUntampered = untamperedRequestObject.getXmlMessageLength();
        requestSizePaddedTampered = this.tamperedRequestObject.getXmlMessageLength();
        requestSizeTestProbe = (int) wsdlRequestOriginal.getContentLength();

        // This model is an Observable -> implemenets ModelSubject!!
        this.listeners = new ArrayList<AttackListener>();

        // Attack time logging
        this.logList = new ArrayList<LogEntryRequest>();
        this.logListUntamperedRequests = new ArrayList<LogEntryRequest>();
        this.logListTamperedRequests = new ArrayList<LogEntryRequest>();
        this.logListTestProbeRequests = new ArrayList<LogEntryRequest>();
        this.logListNetworktestRequests = new ArrayList<LogEntryRequest>();

        // set State
        this.currentAttackState = this.stateArray[0];
    }

    /*
     * ----------------------------------------------- Listeners of the Model that get informed when Model is changed
     * -----------------------------------------------
     */
    /*
     * add listeners
     * @param l
     */
    @Override
    public void addAttackListener( AttackListener l )
    {
        listeners.add( l );
    }

    /**
     * remove listeners!
     */
    @Override
    public void removeAttackListener( AttackListener l )
    {
        listeners.remove( l );
    }

    /**
     * causes all listeners to be updated
     */
    private void fireModelChanged()
    {
        for ( AttackListener l : listeners )
        {
            l.valueChanged( this );
        }
    }

    public List<LogEntryRequest> getLogList()
    {
        return logList;
    }

    public List<LogEntryRequest> getLogListUntamperedRequests()
    {
        return logListUntamperedRequests;
    }

    public List<LogEntryRequest> getLogListTamperedRequests()
    {
        return logListTamperedRequests;
    }

    public List<LogEntryRequest> getLogListTestProbeRequests()
    {
        return logListTestProbeRequests;
    }

    // -----------------------------------------------
    // Misc Methods
    // -----------------------------------------------

    /**
     * Gets Progress of Attack for ProgressBar
     */
    public int getProgress()
    {
        float total;
        float current;
        if ( isNetworkTestEnabled() )
        {
            total = ( 2 * numberRequestsPerThread * numberThreads ) + networkTestNumberRequests;
            current = counterRequestsSendTampered + counterRequestsSendUntampered + counterRequestsSendNetworkTest;
        }
        else
        {
            total = 2 * numberRequestsPerThread * numberThreads;
            current = counterRequestsSendTampered + counterRequestsSendUntampered;
        }

        // percentage
        float result = ( current / total ) * 100;
        return (int) result;
    }

    /**
     * Log response Time of Request of all Types Called via InvokeLater-runnable in different Threads -> thats why not
     * syncronized! CALLED IN EDT: - PREVENTS SYNC Problems - GUARANTEES that logging of responses AFTER attack is done
     * 
     * @param type is it a testprobe, tampered or untampered request
     * @param tsSend when was Request send
     * @param tsReceived when was Request Received
     * @param duration ns of roundtriptime
     * @param threadNumber Threadnumber that is responsible for request
     * @param timeOutFlag Did a timeout happen
     * @param faultFlag Did a timeout happen
     * @param responseString Full SOAP-Response of Body
     */
    public synchronized void logResponseTime( String type, long tsSend, long tsReceived, long duration,
                                              int threadNumber, boolean faultFlag, boolean errorflag,
                                              String responseString )
    {

        if ( !this.attackAborted && !this.attackFinished )
        {
            LogEntryRequest logEntry =
                new LogEntryRequest( type, tsSend, tsReceived, duration, threadNumber, faultFlag, errorflag,
                                     responseString );
            logList.add( logEntry );

            if ( type.equals( "untampered" ) )
            {
                this.logListUntamperedRequests.add( logEntry );
            }
            else if ( type.equals( "tampered" ) )
            {
                this.logListTamperedRequests.add( logEntry );
            }
            else if ( type.equals( "testProbe" ) )
            {
                this.logListTestProbeRequests.add( logEntry );
            }
            else if ( type.equals( "networkTest" ) )
            {
                this.logListNetworktestRequests.add( logEntry );
            }
            else
            {
                return;
            }
        }
        else
        {
            // System.out.println("ERROR: Trying To Write Response in aborted or finalized attack!");
        }
    }

    /**
     * Calculates Datastructure for Graph and all other statistical Data Pay attention to the
     * intervalLengthResult-Attribute, it has a major influence on how many datapoints are shown in result graph!
     */
    public void generateResults()
    {
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Trace, "attackModel", "Generate Results - start" ) );

        // gucke wie viel Sekunden die Attacke insgesamt gelaufen ist
        int secondsTotal = (int) ( ( this.tsAttackStop - this.tsAttackStart ) / 1000 );
        int currentMillisecond = 0;
        int matchingInterval = 0;
        long currentDuration; // ns / 1000000
        mapLogEntryIntervalUntampered = new HashMap<Integer, LogEntryInterval>();
        mapLogEntryIntervalTampered = new HashMap<Integer, LogEntryInterval>();
        mapLogEntryIntervalTestProbe = new HashMap<Integer, LogEntryInterval>();

        // loop all UNtampered Requests and group in discrete intervals as
        // defined in intervalLengthReport
        for ( LogEntryRequest currentLogEntryUntampered : this.logListUntamperedRequests )
        {
            writeLogEntryRequestToLogEntryInterval( mapLogEntryIntervalUntampered, currentLogEntryUntampered );
        }

        // loop all Tampered Requests and group in discrete intervals as defined
        // in intervalLengthReport
        for ( LogEntryRequest currentLogEntryTampered : this.logListTamperedRequests )
        {
            writeLogEntryRequestToLogEntryInterval( mapLogEntryIntervalTampered, currentLogEntryTampered );
        }

        // loop all TestProbe requests and group in discrete intervals as
        // defined in intervalLengthReport
        for ( LogEntryRequest currentLogEntryTestProbe : this.logListTestProbeRequests )
        {
            writeLogEntryRequestToLogEntryInterval( mapLogEntryIntervalTestProbe, currentLogEntryTestProbe );
        }

        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Trace, "attackModel", "Generate Results - end" ) );
    }

    public void writeLogEntryRequestToLogEntryInterval( Map<Integer, LogEntryInterval> mapLogEntryInterval,
                                                        LogEntryRequest currentLogEntryRequest )
    {

        // number seconds elapsed since start of attack (ms)
        int currentMillisecond = (int) ( ( currentLogEntryRequest.getTsSend() - this.tsAttackStart ) );
        long currentDuration = currentLogEntryRequest.getDuration() / 1000000;
        LogEntryInterval currentLogEntryInterval;

        // calculate interval for current LogEntryRequest
        int matchingInterval = currentMillisecond - ( currentMillisecond % this.intervalLengthReport );

        // create new currentLogEntryInterval-Object or load existing one
        // test if currentMillisecond matches existing
        // currentLogEntryInterval-Object, if NO, create new one and add
        if ( mapLogEntryInterval.get( matchingInterval ) == null )
        {
            currentLogEntryInterval = new LogEntryInterval();
            currentLogEntryInterval.setIntervalNumber( matchingInterval );
            mapLogEntryInterval.put( currentLogEntryInterval.getIntervalNumber(), currentLogEntryInterval );
            // System.out.println("New Untampered IntervalArrayEntry = " +
            // currentLogEntryInterval.getIntervalNumber() + " w ");
        }
        else
        {
            currentLogEntryInterval = mapLogEntryInterval.get( matchingInterval );
        }

        // write currentLogEntryRequest-ResponseTime in LogEntryInterval-Object
        // in mapLogEntryInterval-ObjectMap
        if ( currentLogEntryInterval.getMeanResponseTime() > 0 )
        {
            currentLogEntryInterval.setMeanResponseTime( ( currentLogEntryInterval.getMeanResponseTime() + currentDuration ) / 2 );
        }
        else
        {
            currentLogEntryInterval.setMeanResponseTime( currentDuration );
        }
        currentLogEntryInterval.incNumberRequests();
        // System.out.println("Update xx IntervalArrayEntry = IntervalNumber: "
        // + currentLogEntryInterval.getIntervalNumber() + " with currentMean: "
        // + currentLogEntryInterval.getMeanResponseTime() + " - mit " +
        // currentLogEntryInterval.getNumberRequests() + " Requests");
    }

    /**
     * metric used to test for vulnerability Sets responseTimeMeanUntampered and responseTimeMeanTampered in relation
     * <ul>
     * <li>Result = 1: <br />
     * No difference between tampered and untampered requests</li>
     * <li>Result &lt; 1: <br />
     * response time of tampered Requests is even lower than the response time of untampered requests -> attack not
     * successful!</li>
     * <li>Result &gt; 1: <br />
     * response time of tampered Requests are higher than response time of untampered requests. In this case the attack
     * is successful! The attack can be considered as a success when the result is higher than 2 points</li>
     * </ul>
     * Defined as: (responseTimeMeanTampered / responseTimeMeanUntampered)
     * 
     * @return Points
     */
    public double getAttackRoundtripTimeRatio()
    {
        try
        {
            Median median = new Median();
            int sampleCountMax =
                ( logListUntamperedRequests.size() < sampleCountAttackEffectivness ) ? logListUntamperedRequests.size()
                                : sampleCountAttackEffectivness;

            // Loop last 10 untampered AttackRequests and calculate median
            medianUntampered = 0;
            double[] medianUntamperedArray = new double[sampleCountMax];
            for ( int i = 1; i <= sampleCountMax; i++ )
            {
                medianUntamperedArray[i - 1] =
                    logListUntamperedRequests.get( logListUntamperedRequests.size() - i ).getDuration();
            }
            medianUntampered = median.evaluate( medianUntamperedArray );

            // Loop last 10 tampered AttackRequests and calculate median
            medianTampered = 0;
            double[] medianTamperedArray = new double[sampleCountMax];
            for ( int i = 1; i <= sampleCountMax; i++ )
            {
                medianTamperedArray[i - 1] =
                    logListTamperedRequests.get( logListTamperedRequests.size() - i ).getDuration();
            }
            medianTampered = median.evaluate( medianTamperedArray );

            double timeDelta = ( (float) medianTampered / (float) ( medianUntampered ) );
            double result = timeDelta; // ns = 10^9 to delta_ms
            if ( result >= 0 )
            {
                return Math.round( result * 100.0 ) / 100.0;
            }
            else
            {
                return 0.0;
            }
        }
        catch ( Exception e )
        {
            return 0.0;
        }
    }

    /*
     * get text for RatioRequestsize result
     * @return
     */
    public String getAttackRoundtripTimeRatioDescription( String type )
    {
        String text = "";
        String image = "";
        if ( getAttackRoundtripTimeRatio() < payloadSuccessThreshold )
        {
            text = "payload ineffective";
            image = "/IMG/statusGreen.png";
        }
        else if ( getAttackRoundtripTimeRatio() < 6 )
        {
            text = "payload effective";
            image = "/IMG/statusOrange.png";
        }
        else if ( getAttackRoundtripTimeRatio() >= 6 )
        {
            text = "payload higly effective";
            image = "/IMG/statusRed.png";
        }

        if ( type.equals( "image" ) )
        {
            return image;
        }
        else
        {
            return text;
        }
    }

    /**
     * Calculate Attack effectivness 2 - attack efficiency (size) under given load scenario. Sets requestSizeTampered
     * and requestSizeUntampered in relation The results should be interpreted as follows:
     * <ul>
     * <li>Result = 1: <br />
     * Size of attack request is equal to the size of untampered attack
     * <li>Result &lt; 1: <br />
     * size of untampered request is lower than the size of tampered request.
     * <li>Result &gt; 1: <br />
     * size of untampered request is higher than the size of tampered request.
     * </ul>
     * The higher the result the higher the attack efficincy. Defined as: (requestSizeUntampered / requestSizeTampered)
     * 
     * @return percent
     */
    public double getAttackRatioRequestsize()
    {
        try
        {
            double sizeDelta = (float) this.requestSizeTestProbe / (float) this.requestSizeTampered;
            double result = sizeDelta; // ns = 10^9 to delta_ms
            if ( result >= 0 )
            {
                return Math.round( result * 100.0 ) / 100.0;
            }
            else
            {
                return 0.0;
            }
        }
        catch ( Exception e )
        {
            return 0.0;
        }
    }

    /**
     * get text for RatioRequestsize result
     * 
     * @return
     */
    public String getAttackRatioRequestsizeDescription( String type )
    {
        String text = "";
        String image = "";
        if ( getAttackRatioRequestsize() <= 0.5 )
        {
            text = "inefficient attack";
            image = "/IMG/statusGreen.png";
        }
        else if ( getAttackRatioRequestsize() > 0.5 && getAttackRatioRequestsize() <= 2 )
        {
            text = "neutral result";
            image = "/IMG/statusGrey.png";
        }
        else if ( getAttackRatioRequestsize() > 2 && getAttackRatioRequestsize() <= 5 )
        {
            text = "efficient attack";
            image = "/IMG/statusRed.png";
        }
        else if ( getAttackRatioRequestsize() > 5 )
        {
            text = "highly efficient attack";
            image = "/IMG/statusRed.png";
        }

        if ( type.equals( "image" ) )
        {
            return image;
        }
        else
        {
            return text;
        }
    }

    /**
     * Calculate attack effect on third party users. Output ms of mean of all testprobe requests after attack started
     * Makes a statement in regard of longterm effect on thrid party users!
     * 
     * @return
     */
    public double getTestProbeAttackRoundtripTime()
    {
        // Only if attack is effective
        if ( getAttackRoundtripTimeRatio() > payloadSuccessThreshold )
        {
            // Only if we have data
            if ( logListTestProbeRequests.size() > 0 )
            {
                Median median = new Median();
                int sampleCountMaxTestProbes = 0;

                // Count number of suitable logRequestObjectss
                for ( int i = 0; i < logListTestProbeRequests.size(); i++ )
                {
                    if ( logListTestProbeRequests.get( i ).getTsSend() > tsTamperedLastSend )
                    {
                        sampleCountMaxTestProbes++;
                        // System.out.println(sampleCountMaxTestProbes+" - "+logListTestProbeRequests.get(i).getTsSend()
                        // +" - "+ tsTamperedLastSend);
                    }
                }
                double[] medianTestProbesArray = new double[sampleCountMaxTestProbes];

                // Save duration in array for median
                int k = 0;
                for ( int i = 0; i < logListTestProbeRequests.size(); i++ )
                {
                    if ( logListTestProbeRequests.get( i ).getTsSend() > tsTamperedLastSend )
                    {
                        medianTestProbesArray[k] = logListTestProbeRequests.get( i ).getDuration();
                        k++;
                    }
                }
                double medianTestProbes = median.evaluate( medianTestProbesArray );
                double result = medianTestProbes / 1000000000;
                return Math.round( result * 1000.0 ) / 1000.0;
            }
        }
        return 0;
    }

    /**
     * time between sending of last tampered attack and attack finalisation
     * 
     * @return
     */
    public double getAttackLongevitySeconds()
    {
        double result = ( this.tsAttackStop - this.tsTamperedLastSend ) / ( 1000 );
        return Math.round( result * 100.0 ) / 100.0;
    }

    /**
     * get text/image for RatioLongevity
     * 
     * @return
     */
    public String getTestProbeAttackRoundtripTimeDescription( String type )
    {
        String text = "";
        String image = "";

        // Only if attack is effective
        if ( getAttackRoundtripTimeRatio() > payloadSuccessThreshold )
        {
            if ( getTestProbeAttackRoundtripTime() < 2 )
            {
                text = "no or small effect on third party users";// after
                                                                 // "+getAttackRatioLongevitySeconds()+"
                                                                 // sec";
                image = "/IMG/statusGreen.png";
            }
            else if ( getTestProbeAttackRoundtripTime() < 5 )
            {
                text = "third party users are affected";// after
                                                        // "+getAttackRatioLongevitySeconds()+"
                                                        // sec";
                image = "/IMG/statusOrange.png";
            }
            else if ( getTestProbeAttackRoundtripTime() >= 5 )
            {
                text = "third party users are heavily affected";// after
                                                                // "+getAttackRatioLongevitySeconds()+"
                                                                // sec";
                image = "/IMG/statusRed.png";
            }
            else
            {
                text = "no attack effect";// after
                                          // "+getAttackRatioLongevitySeconds()+"
                                          // sec";
                image = "/IMG/statusGreen.png";
            }
        }
        else
        {
            text = "no attack effect";// after
                                      // "+getAttackRatioLongevitySeconds()+"
                                      // sec";
            image = "/IMG/statusGreen.png";
        }

        if ( type.equals( "image" ) )
        {
            return image;
        }
        else
        {
            return text;
        }
    }

    /**
     * return string with all custom attack parameters! REMEMBER: first 6 entries are reserved for standard DOS attack
     * parameters..
     * 
     * @return
     */
    public String getCustomAttackParameters()
    {
        StringBuilder sb = new StringBuilder();
        for ( int i = 7; i < pluginOptions.size(); i++ )
        {
            sb.append( pluginOptions.getByIndex( i ).getName() );
            sb.append( ": " );
            sb.append( pluginOptions.getByIndex( i ).getValueAsString() );
            sb.append( " - " );
            sb.append( pluginOptions.getByIndex( i ).getDescription() );
            sb.append( "\n" );
        }

        return sb.toString();
    }

    // -----------------------------------------------
    // Methods that get called via Controllers
    // -> Controller run in EDT, therefore guranteed that methods that update
    // the GUI also run in EDT
    // -----------------------------------------------

    /**
     * starts the attack! WARNING: is executed in EDT-Thread. Therefore it should never block All lengthy operations
     * should be put in new Thread
     */
    public void startAttack()
    {
        // should never block, otherwise GUI will block!

        // start stopwatch
        this.setClock( new Clock() );
        this.ticker = new TickerThread( this );

        // Log millisecondTs of attack start
        // -> System.currentTimeMillis() VS System.nanoTime();
        this.tsAttackStart = System.currentTimeMillis();

        // start attack Branch-Thread, incl. everything!
        this.performAttackThread = new PerformAttackThread( this );
        this.performAttackThread.start();

        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Trace, "attackModel", "done starting attack: "
                                          + this.attackName ) );

        // inform all listeners
        fireModelChanged();
    }

    /**
     * finalize attack - Ends all Threads - Calculates all Statistics - Show Result in new Jframe!
     * 
     * @return
     */
    public void finalizeAttack()
    {
        // Log millisecondTs of attack completion
        // -> System.currentTimeMillis() VS System.nanoTime();
        this.tsAttackStop = System.currentTimeMillis();

        // stop clock
        if ( this.ticker != null )
        {
            this.ticker.interrupt();
        }

        // SendProbeRequests stoppen (dazu einfach performProbeRequest-Thread
        // interrupten)
        if ( this.sendProbeRequestsThread != null )
        {
            this.sendProbeRequestsThread.interrupt();
        }

        // generate Results
        this.currentAttackState = getStateArray()[8];
        this.generateResults();

        // Change State
        this.attackFinished = true;

        // Alle Listener informieren!
        fireModelChanged();
    }

    /**
     * finalizes the Attack automaticly WITHOUT user interuption - Waits defined number of seconds after last request
     * got in - Ends all Threads - Calculates all Statistics - Show Result in new Jframe!
     * 
     * @return
     */
    public void finalizeAttackAuto()
    {
        // finalize incl generating result
        finalizeAttack();

        // Set StopFlag for all SendRequestThreads
        attackAborted = true;

        // set finished state including WS-Attacker results
        attackFinished = true;

        // set Info
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Info, "Attack Model EDT",
                                                       "Auto Finalization finished, attack closed" ) );
    }

    /**
     * stopps Attack, closes all AttackThreads, keeps GUI running
     * 
     * @return
     */
    public void abortAttack()
    {
        // Set State
        this.currentAttackState = getStateArray()[7];

        // Uhr stoppen (dazu einfach ticker Thread interrupten)
        if ( this.ticker != null )
        {
            this.ticker.interrupt();
        }

        // SendProbeRequests stoppen (dazu einfach performProbeRequest-Thread
        // interrupten)
        if ( this.sendProbeRequestsThread != null )
        {
            this.sendProbeRequestsThread.interrupt();
        }

        // stop PerformAttackThread
        if ( this.performAttackThread != null )
        {
            this.performAttackThread.interrupt();
        }

        // Set StopFlag for all SendRequestThreads
        attackAborted = true;

        // Alle Listener informieren!
        fireModelChanged();
    }

    /**
     * stopps Attack, closes all AttackThreads, closes GUI closes the GUI and goes back to WS-Attacker called only if
     * attack was not completed 100%;
     */
    public void closeAttackUnfinished()
    {
        abortAttack();

        // set finished state including WS-Attacker results
        attackFinished = true;
        this.setWsAttackerResults( "Attack aborted by user" );

        fireModelChanged();
    }

    // ----------------------------------------------
    // Methods that update the GUI
    // -> they all have a fireModelChanged() method)
    // -> these are ONLY called via Runnables (that are executed in EDT-Thread)
    // ----------------------------------------------
    /*
     * Increment NumberRequest, depending on type -> called from EDT, no syncronisation required
     */
    public void incNumberRequests( String type )
    {
        if ( !this.attackAborted && !this.attackFinished )
        {
            if ( type.equals( "tampered" ) )
            {
                this.counterRequestsSendTampered++;
            }
            else if ( type.equals( "untampered" ) )
            {
                this.counterRequestsSendUntampered++;
            }
            else
            {
                System.out.println( "No number incremented" );
            }
            this.fireModelChanged();
        }
        else
        {
            // do nothing - attack is already sdone!
            return;
        }
    }

    /*
     * Increment Number parallel Attack Threads, depending on type
     */
    public void incNumberThreads( String type )
    {
        if ( type.equals( "tampered" ) )
        {
            this.counterThreadsTampered++;
        }
        else
        {
            this.counterThreadsUntampered++;
        }
        this.fireModelChanged();
    }

    /*
     * Increment Number parallel Testprobes send
     */
    public void incNumberProbes()
    {
        this.counterProbesSend++;
        this.fireModelChanged();
    }

    /*
     * Increment Number NetworkTestRequests Send
     */
    public void incNumberNetworktestProbes()
    {
        this.counterRequestsSendNetworkTest++;
        this.fireModelChanged();
    }

    /*
     * updates the state of attack
     * @param currentAttackState
     */
    public void setCurrentAttackState( int currentAttackState )
    {
        this.currentAttackState = this.stateArray[currentAttackState];
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Trace, "attackModel", "Updated state of Attack to: "
                                          + this.currentAttackState ) );
        this.fireModelChanged();
    }

    /*
     * Update Clock!
     * @return
     */
    public void updateClock( String currentTime )
    {
        this.attackTime = currentTime;
        fireModelChanged();
    }

    /**
     * Prints the result of the network stability Test
     */
    public void generateNetworktestResult()
    {
        SummaryStatistics statistics = createNetworkStatistics();

        double standarddeviationResult = statistics.getStandardDeviation();
        double meanResult = statistics.getMean();

        // get Coefficient of variation
        this.networkTestResult = ( standarddeviationResult / meanResult );
        this.networkTestResult = Math.round( networkTestResult * 100.0 ) / 100.0;
        System.out.println( "--------------------Ergebnis NETWORK:" + standarddeviationResult + " - " + meanResult
            + " - " + ( standarddeviationResult / meanResult ) );

        // get Result String
        if ( this.networkTestResult < 0.5 )
        {
            this.networkTestResultString = "stable";
        }
        else if ( this.networkTestResult >= 0.5 && this.networkTestResult < 2.0 )
        {
            this.networkTestResultString = "noisy";
        }
        else
        {
            this.networkTestResultString = "unstable";
        }

        this.networkTestFinished = true;

        fireModelChanged();
    }

    private SummaryStatistics createNetworkStatistics()
    {
        int toSkip = 5;
        // generate Array from LogResults
        // loop all NetworkTestRequests and write to array
        int j = 0;
        SummaryStatistics statistics = new SummaryStatistics();
        for ( LogEntryRequest currentLogEntry : this.logListNetworktestRequests )
        {
            // skip first entries
            if ( j >= toSkip )
            {
                statistics.addValue( currentLogEntry.getDuration() );
                System.out.println( "----add:" + ( j - toSkip ) + " - " + currentLogEntry.getDuration() );
            }
            j++;
        }
        return statistics;
    }

    //
    // ----------------------------------
    // GETTER / SETTER!
    // ----------------------------------
    //
    public String[] getStateArray()
    {
        return stateArray;
    }

    public String getCurrentAttackState()
    {
        return currentAttackState;
    }

    public Clock getClock()
    {
        return clock;
    }

    public void setClock( Clock clock )
    {
        this.clock = clock;
    }

    public String getAttackTime()
    {
        return attackTime;
    }

    public void setAttackTime( String attackTime )
    {
        this.attackTime = attackTime;
    }

    public int getNumberRequestsPerThread()
    {
        return numberRequestsPerThread;
    }

    public void setNumberRequestsPerThread( int numberRequestsPerThread )
    {
        this.numberRequestsPerThread = numberRequestsPerThread;
    }

    public int getNumberThreads()
    {
        return numberThreads;
    }

    public void setNumberThreads( int numberThreads )
    {
        this.numberThreads = numberThreads;
    }

    public int getCounterThreadsTampered()
    {
        return counterThreadsTampered;
    }

    public void setCounterThreadsTampered( int counterThreads )
    {
        this.counterThreadsTampered = counterThreads;
    }

    public int getCounterThreadsUntampered()
    {
        return counterThreadsUntampered;
    }

    public void setCounterThreadsUntampered( int counterThreads )
    {
        this.counterThreadsUntampered = counterThreads;
    }

    public int getCounterRequestsSendTampered()
    {
        return counterRequestsSendTampered;
    }

    public int getCounterRequestsSendUntampered()
    {
        return counterRequestsSendUntampered;
    }

    /**
     * getCounterRequestsSend Syncronized, because directly called from attack Thread
     * 
     * @param tamperedThreadsStillRunning
     */
    public synchronized int getCounterRequestsSend( String requestType )
    {

        if ( requestType.equals( "untampered" ) )
        {
            return counterRequestsSendUntampered;
        }
        else if ( requestType.equals( "tampered" ) )
        {
            return counterRequestsSendTampered;
        }
        else if ( requestType.equals( "networkTest" ) )
        {
            return counterRequestsSendNetworkTest;
        }
        else
        {
            return 0;
        }
    }

    public int getSecondsBetweenProbes()
    {
        return millisecondsBetweenProbes;
    }

    public void setSecondsBetweenProbes( int secondsBetweenProbes )
    {
        this.millisecondsBetweenProbes = secondsBetweenProbes;
    }

    public int getSecondsServerLoadRecovery()
    {
        return millisecondsServerLoadRecovery;
    }

    public void setSecondsServerLoadRecovery( int secondsServerLoadRecovery )
    {
        this.millisecondsServerLoadRecovery = secondsServerLoadRecovery;
    }

    public int getCounterProbesSend()
    {
        return this.counterProbesSend;
    }

    public boolean isAttackAborted()
    {
        return attackAborted;
    }

    public boolean isAttackFinished()
    {
        return this.attackFinished;
    }

    public long getTsAttackStart()
    {
        return tsAttackStart;
    }

    public void setTsAttackStart( long tsAttackStart )
    {
        this.tsAttackStart = tsAttackStart;
    }

    public String getStartDate()
    {
        SimpleDateFormat sdf = new SimpleDateFormat( "HH:mm:ss" ); // yyyy-mm-dd
        Date resultdate = new Date( this.tsAttackStart );
        return sdf.format( resultdate );
    }

    public String getStopDate()
    {
        SimpleDateFormat sdf = new SimpleDateFormat( "HH:mm:ss" ); // yyyy-mm-dd
        Date resultdate = new Date( this.tsAttackStop );
        return sdf.format( resultdate );
    }

    public long getTsAttackStop()
    {
        return tsAttackStop;
    }

    public void setTsAttackStop( long tsAttackStop )
    {
        this.tsAttackStop = tsAttackStop;
    }

    public Map<Integer, LogEntryInterval> getMapLogEntryIntervalUntampered()
    {
        return mapLogEntryIntervalUntampered;
    }

    public void setMapLogEntryIntervalUntampered( Map<Integer, LogEntryInterval> mapLogEntryIntervalUntampered )
    {
        this.mapLogEntryIntervalUntampered = mapLogEntryIntervalUntampered;
    }

    public Map<Integer, LogEntryInterval> getMapLogEntryIntervalTampered()
    {
        return mapLogEntryIntervalTampered;
    }

    public void setMapLogEntryIntervalTampered( Map<Integer, LogEntryInterval> mapLogEntryIntervalTampered )
    {
        this.mapLogEntryIntervalTampered = mapLogEntryIntervalTampered;
    }

    public Map<Integer, LogEntryInterval> getMapLogEntryIntervalTestProbe()
    {
        return mapLogEntryIntervalTestProbe;
    }

    public void setMapLogEntryIntervalTestProbe( Map<Integer, LogEntryInterval> mapLogEntryIntervalTestProbe )
    {
        this.mapLogEntryIntervalTestProbe = mapLogEntryIntervalTestProbe;
    }

    public int getRequestSizeUntampered()
    {
        return requestSizeUntampered;
    }

    public void setRequestSizeUntampered( int requestSizeUntampered )
    {
        this.requestSizeUntampered = requestSizeUntampered;
    }

    public int getRequestSizeTampered()
    {
        return requestSizeTampered;
    }

    public void setRequestSizeTampered( int requestSizeTampered )
    {
        this.requestSizeTampered = requestSizeTampered;
    }

    public int getRequestSizePaddedTampered()
    {
        return requestSizePaddedTampered;
    }

    public int getRequestSizePaddedUntampered()
    {
        return requestSizePaddedUntampered;
    }

    public int getRequestSizeTestProbe()
    {
        return requestSizeTestProbe;
    }

    public void setRequestSizeTestProbe( int requestSizeTestProbe )
    {
        this.requestSizeTestProbe = requestSizeTestProbe;
    }

    public void setTsTamperedStart( long ts )
    {
        this.tsTamperedStart = ts;

    }

    public long getTsUntamperedStart()
    {
        return tsUntamperedStart;
    }

    public void setTsTamperedLastSend( long ts )
    {
        this.tsTamperedLastSend = ts;

    }

    public long getTsTamperedLastSend()
    {
        return tsTamperedLastSend;
    }

    public void setTsUntamperedStart( long tsUntamperedStart )
    {
        this.tsUntamperedStart = tsUntamperedStart;
    }

    public String getAttackName()
    {
        return attackName;
    }

    public void setAttackName( String attackName )
    {
        this.attackName = attackName;
    }

    public String getWsdlUrl()
    {
        return wsdlUrl;
    }

    public void setWsdlUrl( String wsdlUrl )
    {
        this.wsdlUrl = wsdlUrl;
    }

    public String getIp()
    {
        return ip;
    }

    public void setIp( String ip )
    {
        this.ip = ip;
    }

    public String getAttackDescription()
    {
        return attackDescription;
    }

    public void setAttackDescription( String attackDescription )
    {
        this.attackDescription = attackDescription;
    }

    public String getAttackCountermeasures()
    {
        return attackCountermeasures;
    }

    public void setAttackCountermeasures( String attackCountermeasures )
    {
        this.attackCountermeasures = attackCountermeasures;
    }

    public String getWsAttackerResults()
    {
        return wsAttackerResults;
    }

    public void setWsAttackerResults( String wsAttackerResults )
    {
        this.wsAttackerResults = wsAttackerResults;
    }

    public int getWsAttackerPoints()
    {
        if ( this.getAttackRoundtripTimeRatio() > this.payloadSuccessThreshold )
        {
            // TODO [CHAL 2014-02-13] why 16 ???
            int result = (int) ( this.getAttackRoundtripTimeRatio() * 16 ); // magic
                                                                            // number
            if ( result > MAX_POINTS )
            {
                return MAX_POINTS;
            }
            else
            {
                return result;
            }
        }
        else
        {
            return 1;
        }
    }

    public int getSecondsBetweenRequests()
    {
        return millisecondsBetweenRequests;
    }

    public void setSecondsBetweenRequests( int secondsBetweenRequests )
    {
        this.millisecondsBetweenRequests = secondsBetweenRequests;
    }

    public int getRequestsTotal()
    {
        return ( numberRequestsPerThread * numberThreads );
    }

    public WsdlRequest getWsdlRequestOriginal()
    {
        return wsdlRequestOriginal;
    }

    public void setWsdlRequestOriginal( WsdlRequest wsdlRequestOriginal )
    {
        this.wsdlRequestOriginal = wsdlRequestOriginal;
    }

    public WsdlResponse getWsdlResponseOriginal()
    {
        return wsdlResponseOriginal;
    }

    public void setWsdlResponseOriginal( WsdlResponse wsdlResponseOriginal )
    {
        this.wsdlResponseOriginal = wsdlResponseOriginal;
    }

    public int getIntervalLengthReport()
    {
        return intervalLengthReport;
    }

    public void setIntervalLengthReport( int intervalLengthReport )
    {
        this.intervalLengthReport = intervalLengthReport;
    }

    public boolean isAutoFinalizeSwitch()
    {
        return autoFinalizeSwitch;
    }

    public void setAutoFinalizeSwitch( boolean autoFinalizeSwitch )
    {
        this.autoFinalizeSwitch = autoFinalizeSwitch;
    }

    public int getAutoFinalizeSeconds()
    {
        return autoFinalizeMilliSeconds;
    }

    public void setAutoFinalizeSeconds( int autoFinalizeSeconds )
    {
        this.autoFinalizeMilliSeconds = autoFinalizeSeconds;
    }

    public boolean isNetworkTestEnabled()
    {
        return networkTestEnabled;
    }

    public void setNetworkTestEnabled( boolean networkTestEnabled )
    {
        this.networkTestEnabled = networkTestEnabled;
    }

    public int getNetworkTestNumberRequests()
    {
        return networkTestNumberRequests;
    }

    public void setNetworkTestNumberRequests( int networkTestNumberRequests )
    {
        this.networkTestNumberRequests = networkTestNumberRequests;
    }

    public int getNetworkTestRequestInterval()
    {
        return networkTestRequestIntervalInMilliseconds;
    }

    public void setNetworkTestRequestInterval( int networkTestRequestInterval )
    {
        this.networkTestRequestIntervalInMilliseconds = networkTestRequestInterval;
    }

    public double getNetworkTestResult()
    {
        return networkTestResult;
    }

    public void setNetworkTestResult( double networkTestResult )
    {
        this.networkTestResult = networkTestResult;
    }

    public Thread getSendProbeRequestsThread()
    {
        return sendProbeRequestsThread;
    }

    public void setSendProbeRequestsThread( Thread sendProbeRequestsThread )
    {
        this.sendProbeRequestsThread = sendProbeRequestsThread;
    }

    public String getNetworkTestResultString()
    {
        return networkTestResultString;
    }

    public void setNetworkTestResultString( String networkTestResultString )
    {
        this.networkTestResultString = networkTestResultString;
    }

    public boolean isNetworkTestFinished()
    {
        return networkTestFinished;
    }

    public void setNetworkTestFinished( boolean networkTestFinished )
    {
        this.networkTestFinished = networkTestFinished;
    }

    public RequestObject getTamperedRequestObject()
    {
        return tamperedRequestObject;
    }

    public void setTamperedRequestObject( RequestObject tamperedRequestObject )
    {
        this.tamperedRequestObject = tamperedRequestObject;
    }

    public RequestObject getUntamperedRequestObject()
    {
        return untamperedRequestObject;
    }

    public void setUntamperedRequestObject( RequestObject untamperedRequestObject )
    {
        this.untamperedRequestObject = untamperedRequestObject;
    }

    public Map<String, String> getOriginalRequestHeaderFields()
    {
        return originalRequestHeaderFields;
    }

    public void setOriginalRequestHeaderFields( Map<String, String> originalRequestHeaderFields )
    {
        this.originalRequestHeaderFields = originalRequestHeaderFields;
    }

    public double getMedianUntampered()
    {
        return medianUntampered;
    }

    public void setMedianUntampered( double medianUntampered )
    {
        this.medianUntampered = medianUntampered;
    }

    public double getMedianTampered()
    {
        return medianTampered;
    }

    public void setMedianTampered( double medianTampered )
    {
        this.medianTampered = medianTampered;
    }

}
