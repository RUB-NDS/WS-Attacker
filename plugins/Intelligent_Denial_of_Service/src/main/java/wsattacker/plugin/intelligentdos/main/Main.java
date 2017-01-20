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
package wsattacker.plugin.intelligentdos.main;

import com.eviware.soapui.DefaultSoapUICore;
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
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.xmlbeans.XmlException;
import wsattacker.gui.component.log.GuiAppender;
import wsattacker.library.intelligentdos.IntelligentDoSLibraryImpl;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.XmlEntityExpansion;
import wsattacker.library.intelligentdos.position.PositionIterator;
import wsattacker.library.intelligentdos.position.SchemaAnalyzerPositionIterator;
import wsattacker.library.intelligentdos.success.SimpleSuccessDecider;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.main.testsuite.CurrentRequest;
import wsattacker.plugin.intelligentdos.listener.AttackModelChangeListener;
import wsattacker.plugin.intelligentdos.worker.IntelligentDoSWorker;

public class Main
{

    private static final int APACHE = 0;

    private static final int DOTNET = 1;

    private static final int RUB = 2;

    private static Logger LOG;

    private static String fileName = "";

    public static void main( String[] args )
    {
        if ( args.length > 100 )
        {
            commandLineParser( args );
        }

        // reads the file name as first parameter
        // Signed_Request.xml
        fileName = args[0];

        initLoggers();

        long start = System.currentTimeMillis();

        try
        {
            CurrentRequest original = create();

            SchemaAnalyzer schemaAnalyzer = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );
            String xmlMessage = original.getWsdlRequest().getRequestContent();
            PositionIterator positionIterator = new SchemaAnalyzerPositionIterator( schemaAnalyzer, xmlMessage );

            IntelligentDoSLibraryImpl intelligentDoSLibraryImpl =
                new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );

            intelligentDoSLibraryImpl.setAttacks( new DoSAttack[] { new XmlEntityExpansion() } );
            intelligentDoSLibraryImpl.setSuccessDecider( new SimpleSuccessDecider() );
            // intelligentDoSLibraryImpl.setCommonParams( commonParamList );
            intelligentDoSLibraryImpl.setServerRecoveryTime( 20000 );
            intelligentDoSLibraryImpl.initialize();

            IntelligentDoSWorker doSWorker = new IntelligentDoSWorker( intelligentDoSLibraryImpl );
            doSWorker.addListener( new AttackModelChangeListener()
            {
                private int count = 0;

                @Override
                public void attackModelChanged( AttackModel attackModel )
                {
                }
            } );
            doSWorker.startAttack( original );

            long stop = System.currentTimeMillis();
        }
        catch ( RuntimeException e )
        {
            throw e;
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }

        System.exit( 0 );
    }

    private static void commandLineParser( String[] args )
    {
        // create the command line parser
        CommandLineParser parser = new BasicParser();

        Options options = new Options();
        Option help = new Option( "help", "print this message" );
        options.addOption( OptionBuilder.withArgName( "url" ).hasArg().withDescription( "use given url" ).create( "url" ) );
        options.addOption( help );

        try
        {
            // parse the command line arguments
            CommandLine line = parser.parse( options, args );

            // has the buildfile argument been passed?
            if ( line.hasOption( "url" ) )
            {
                // initialise the member variable

            }

            // automatically generate the help statement
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp( "Main", options );

        }
        catch ( ParseException exp )
        {
        }

        // System.exit( 0 );
    }

    private static CurrentRequest create()
        throws XmlException, IOException, SoapUIException, SubmitException
    {

        // System.setProperty("http.proxyHost", "sbrproxy1.eur.ad.sag");
        // System.setProperty("http.proxyPort", "3103");

        String[] operations = { "reverser", "Reverser", "calculateSecret" };

        int current = APACHE;

        // create new project
        WsdlProject project = new WsdlProject();

        // import amazon wsdl
        String host = "pcy1095502";// gegenüber
        String port = "8080";
        // String url = "http://" + host + ":" + port + "/Axis2WS/services/Converter?wsdl";
        // String url = "http://" + host + ":" + port
        // + "/CXFWS/services/ConverterPort?wsdl";
        // String url =
        // "http://172.30.11.248:8080/Axis2WS/services/Converter?wsdl"; // VM
        // String url = "http://localhost:8080/Axis2WS/services/Converter?wsdl";
        String url = "http://" + host + ":" + port + "/AxisWS/wsdl/Converter.wsdl";
        // String url = "http://" + host + ":" + port
        // + "/CXFWS/services/ConverterPort?wsdl";
        // String url =
        // "http://cryptochallenge.nds.rub.de:8080/axis2/services/Calculator?wsdl";
        WsdlInterfaceFactory.importWsdl( project, url, false );

        // Soap11 or Soap 12
        WsdlInterface service = (WsdlInterface) project.getInterfaceAt( 0 );
        WsdlOperation wsdlOperation = service.getOperationByName( operations[current] );

        // create a new empty request for that operation
        WsdlRequest wsdlRequest = wsdlOperation.addNewRequest( "Basic Request" );
        String requestContent = wsdlOperation.createRequest( true );

        switch ( current )
        {
            case APACHE:
            case DOTNET:
                requestContent = requestContent.replace( ">?</", ">Lorem ipsum dolor sit amet</" );
                wsdlRequest.setRequestContent( requestContent );
                break;
            case RUB:
                String readFileToString = FileUtils.readFileToString( new File( fileName ) );
                wsdlRequest.setRequestContent( readFileToString );
                break;
            default:
                throw new IllegalArgumentException( current + " is not allowed" );
        }

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
        return original;
    }

    private static void initLoggers()
    {
        // Set Logger options
        LOG = Logger.getRootLogger();
        Logger.getRootLogger().removeAllAppenders();
        PatternLayout layout = new PatternLayout( "%d{ABSOLUTE} %-5p [%c{1}] %m%n" );
        LOG.addAppender( new ConsoleAppender( layout ) );
        LOG.addAppender( new GuiAppender() );

        // soapui logger
        // Logger.getLogger( "com.eviware.soapui" ).setLevel( Level.OFF );
        // Logger.getLogger( DefaultSoapUICore.class ).setLevel( Level.OFF );
        // Logger.getLogger( "com.eviware.soapui.impl" ).setLevel( Level.OFF );

        LOG = Logger.getLogger( Main.class );
        // LOG.setLevel( Level.INFO );
    }

}
