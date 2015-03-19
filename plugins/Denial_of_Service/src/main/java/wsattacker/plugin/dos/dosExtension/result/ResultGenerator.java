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
package wsattacker.plugin.dos.dosExtension.result;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;

import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.plugin.dos.dosExtension.chart.ChartObject;
import wsattacker.plugin.dos.dosExtension.desktop.OpenURI;
import wsattacker.plugin.dos.dosExtension.logEntry.LogEntryRequest;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;
import wsattacker.plugin.dos.dosExtension.zip.Zip;

public class ResultGenerator
{

    // Attack result save variables
    private String fullPath;

    private String filenameReport;

    private final AttackModel attackModel;

    // Refernece to JChartPanel for easy update
    private ChartPanel chartPanel;

    public ResultGenerator( AttackModel attackModel )
    {
        this.attackModel = attackModel;
    }

    public AttackModel getAttackModel()
    {
        return attackModel;
    }

    public String getFullPath()
    {
        return fullPath;
    }

    public void setFullPath( String fullPath )
    {
        this.fullPath = fullPath;
    }

    public String getFilenameReport()
    {
        return filenameReport;
    }

    public void setFilenameReport( String filenameReport )
    {
        this.filenameReport = filenameReport;
    }

    public ChartPanel getJChartPanel()
    {
        return chartPanel;
    }

    public void setJChartPanel( ChartPanel JChartPanel )
    {
        this.chartPanel = JChartPanel;
    }

    /*
     * Open Results in Browserwindow
     */
    public void openResults()
    {

        // Save Results to Zip
        saveResult();

        // Open Results in Browser!
        if ( this.fullPath != null && this.filenameReport != null )
        {
            File report = new File( this.fullPath, this.filenameReport );
            new OpenURI( report );
        }
        else
        {
            Result.getGlobalResult().add( new ResultEntry( ResultLevel.Critical, "attackModel",
                                                           "No resultfiles found in the operating system specific temporary folder" ) );
        }
    }

    /**
     * Save Attack Results to CSV-Files! Location is tmp folder
     */
    public void saveResult()
    {
        String attackName = "DOS";
        SimpleDateFormat sdf = new SimpleDateFormat( "yyyy-MM-dd_HHmm" ); // yyyy-mm-dd
        Date resultdate = new Date( attackModel.getTsAttackStop() );
        String dateString = sdf.format( resultdate );
        String filenameUntampered = dateString + "_" + attackName + "_untamperedRequests.csv";
        String filenameTampered = dateString + "_" + attackName + "_tamperedRequests.csv";
        String filenameTestprobe = dateString + "_" + attackName + "_testprobeRequests.csv";
        String filenameMetadata = dateString + "_" + attackName + "_metaData.txt";
        String filenameImgGraph = dateString + "_" + attackName + "_graph.png";
        String filenameReport = dateString + "_" + attackName + "_results.html";
        String filenameZip = dateString + "_" + attackName + "_results.zip";

        // read tmpDir
        String property = "java.io.tmpdir";
        String tempDir = System.getProperty( property );
        // System.out.println("OS current temporary directory is " + tempDir);
        // make Folders
        File resultDir = new File( tempDir + "/wsattackerdos" );
        if ( !resultDir.exists() )
        { // if the directory does not exist, create it
            resultDir.mkdir();
        }
        File file = new File( tempDir + "/wsattackerdos/" + dateString );
        file.mkdir();
        String fullPath = file.getAbsolutePath();

        try
        {
            File untamperedRequests = new File( fullPath, filenameUntampered );
            saveResponseTimeOfUntamperedRequests( untamperedRequests );

            File tamperedRequests = new File( fullPath, filenameTampered );
            saveResponseTimeOfTamperedRequests( tamperedRequests );

            File testRequests = new File( fullPath, filenameTestprobe );
            saveResponseTimeOfTestRequests( testRequests );

            File metadata = new File( fullPath, filenameMetadata );
            saveMetadata( metadata );

            saveFilelocationToReport( dateString, filenameUntampered, filenameTampered, filenameTestprobe,
                                      filenameMetadata, filenameImgGraph, filenameReport, filenameZip, fullPath );
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        // copy image from .jar to resultDir
        URL inputUrl;
        inputUrl = getClass().getResource( "/IMG/ok.jpg" );
        File dest = new File( fullPath + "/ok.jpg" );
        try
        {
            FileUtils.copyURLToFile( inputUrl, dest );
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }

        // Write Image
        try
        {
            ChartObject chartObject = new ChartObject( attackModel );
            JFreeChart chart = chartObject.createOverlaidChart();
            ChartUtilities.saveChartAsPNG( new File( fullPath + filenameImgGraph ), chart, 900, 700 );
        }
        catch ( IOException e )
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // Create ZipFile in same folder
        Zip.createZip( fullPath, filenameZip );

        // Save Pointers to files
        this.setFullPath( fullPath );
        this.setFilenameReport( filenameReport );

    }

    private void saveResponseTimeOfUntamperedRequests( File untamperedRequests )
        throws IOException
    {
        // Save responseTime of untampered requestProbes!
        FileWriter writer = new FileWriter( untamperedRequests );

        saveResponseTime( writer, attackModel.getLogListUntamperedRequests() );

        writer.flush();
        writer.close();
    }

    private void saveResponseTimeOfTamperedRequests( File tamperedRequests )
        throws IOException
    {
        // Save responseTime of tampered requests!
        FileWriter writer = new FileWriter( tamperedRequests );

        saveResponseTime( writer, attackModel.getLogListTamperedRequests() );

        writer.flush();
        writer.close();
    }

    private void saveResponseTimeOfTestRequests( File testRequests )
        throws IOException
    {
        // Save responseTime of TestProbes!
        FileWriter writer = new FileWriter( testRequests );

        saveResponseTime( writer, attackModel.getLogListTestProbeRequests() );

        writer.flush();
        writer.close();
    }

    private void saveResponseTime( Writer writer, List<LogEntryRequest> responseTimes )
        throws IOException
    {
        for ( LogEntryRequest logEntry : responseTimes )
        {
            writer.append( String.valueOf( logEntry.getTsReceived() ) ); // TsSend
            writer.append( ',' );
            writer.append( String.valueOf( logEntry.getTsSend() ) ); // TsReceived
            writer.append( ',' );
            writer.append( String.valueOf( logEntry.getDuration() ) ); // duration
            writer.append( ',' );
            // thread Number
            writer.append( String.valueOf( logEntry.getThreadNumber() ) );
            writer.append( ',' );
            writer.append( String.valueOf( logEntry.getFaultFlag() ) ); // FaultFlag
            writer.append( ',' );
            writer.append( String.valueOf( logEntry.getErrorFlag() ) ); // ErrorFlag
            writer.append( ',' );
            writer.append( String.valueOf( logEntry.getResponseStringCsv() ) ); // response
            writer.append( '\n' );
        }
    }

    private void saveMetadata( File metadata )
        throws IOException
    {
        // Save Metadata to file
        FileWriter writer = new FileWriter( metadata );

        // Attack Name + Target
        writer.append( "+++++++++++++++++++++++++++\n" );
        writer.append( "Attack Summary\n" );
        writer.append( "+++++++++++++++++++++++++++\n" );
        writer.append( "attack Name: " + attackModel.getAttackName() );
        writer.append( "\n\n" );
        writer.append( "Attack Description:\n" );
        writer.append( "-------------------\n" );
        writer.append( attackModel.getAttackDescription() );
        writer.append( "\n\n" );
        writer.append( "Attack Countermeasures:\n" );
        writer.append( "-----------------------\n" );
        writer.append( attackModel.getAttackCountermeasures() );
        writer.append( "\n\n" );
        writer.append( "+++++++++++++++++++++++++++\n" );
        writer.append( "Attack Metadata:" );
        writer.append( "\n\n" );
        writer.append( "" + "Attack start: " + attackModel.getStartDate() + "\n" + "Attack stop: "
            + attackModel.getStopDate() + "\n" + "Parallel threads: " + attackModel.getNumberThreads() + "\n"
            + "Requests per thread: " + attackModel.getNumberRequestsPerThread() + "\n" + "Request repeat interval: "
            + ( attackModel.getSecondsBetweenRequests() ) + " ms\n" + "Server recovery time: "
            + ( attackModel.getSecondsServerLoadRecovery() / 1000 ) + " sec\n" + "Send testprobes: "
            + attackModel.getCounterProbesSend() + "\n" + "Testprobe repeat interval: "
            + ( attackModel.getSecondsBetweenProbes() ) + " ms\n" + "Size testprobe request: "
            + attackModel.getRequestSizeTestProbe() + " Bytes\n" + "Size untampered request: "
            + attackModel.getRequestSizeUntampered() + " Bytes\n" + "Size tampered request: "
            + attackModel.getRequestSizeTampered() + " Bytes\n" + "Size untampered padded request: "
            + attackModel.getRequestSizePaddedUntampered() + " Bytes\n" + "Size tampered padded request: "
            + attackModel.getRequestSizePaddedTampered() + " Bytes\n" + "Median response time untampered requests: "
            + attackModel.getMedianUntampered() + " ms\n" + "Median response time tampered requests: "
            + attackModel.getMedianTampered() + " ms\n" + "Auto finialize attack switch: "
            + attackModel.isAutoFinalizeSwitch() + "\n" + "Auto finialize attack duration: "
            + attackModel.getAutoFinalizeSeconds() + " seconds\n" + "\n" );
        writer.append( "Custom Attack parameters: \n" );
        writer.append( attackModel.getCustomAttackParameters() );
        writer.append( "\n\n" );
        writer.append( "+++++++++++++++++++++++++++\n" );
        writer.append( "Attack Success Metric - see help file for more info:" );
        writer.append( "\n\n" );
        writer.append( "Attack roundtrip time ratio: " + attackModel.getAttackRoundtripTimeRatio() + " Points - "
            + attackModel.getAttackRoundtripTimeRatioDescription( "text" ) );
        writer.append( "\n\n" );
        writer.append( "Request size ratio: " + attackModel.getAttackRatioRequestsize() + " Points - "
            + attackModel.getAttackRatioRequestsizeDescription( "text" ) );
        writer.append( "\n\n" );

        writer.append( "testprobe roundtrip time after attack (length " + attackModel.getAttackLongevitySeconds()
            + " sec): " + attackModel.getTestProbeAttackRoundtripTime() + " seconds - "
            + attackModel.getTestProbeAttackRoundtripTimeDescription( "text" ) );
        writer.append( "\n\n" );
        writer.append( "+++++++++++++++++++++++++++\n" );
        writer.append( "Requests:" );
        writer.append( "\n\n" );
        writer.append( "target Endpoint: " + attackModel.getWsdlUrl() );
        writer.append( "\n\n" );
        writer.append( "Testprobe Request:\n" );
        writer.append( "------------------\n" );
        Iterator<String> iterator = attackModel.getOriginalRequestHeaderFields().keySet().iterator();
        while ( iterator.hasNext() )
        {
            String key = iterator.next();
            String value = attackModel.getOriginalRequestHeaderFields().get( key ).toString();
            writer.append( key ).append( ": " ).append( value ).append( "\n" );
        }
        writer.append( "\n" );
        writer.append( attackModel.getWsdlRequestOriginal().getRequestContent() );
        writer.append( "\n\n" );
        writer.append( "Untampered Request:\n" );
        writer.append( "-------------------\n" );
        writer.append( attackModel.getUntamperedRequestObject().getHeaderString( "\n" ) );
        writer.append( "\n" );
        writer.append( attackModel.getUntamperedRequestObject().getXmlMessage() );
        writer.append( "\n\n" );
        writer.append( "Tampered Request:\n" );
        writer.append( "-----------------\n" );
        writer.append( attackModel.getTamperedRequestObject().getHeaderString( "\n" ) );
        writer.append( "\n" );
        writer.append( attackModel.getTamperedRequestObject().getXmlMessage() );

        writer.flush();
        writer.close();
    }

    private void saveFilelocationToReport( String dateString, String filenameUntampered, String filenameTampered,
                                           String filenameTestprobe, String filenameMetadata, String filenameImgGraph,
                                           String filenameReport, String filenameZip, String fullPath )
        throws IOException
    {
        // Write Filelocation to report.html-File:
        String htmlString =
            "" + "<html>" + "<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head>"
                + "<body>" + "<h1>Attack Report for '"
                + attackModel.getAttackName()
                + "' - created: "
                + dateString
                + "</h1>"
                + "<p><img src='ok.jpg'/>Attack report generated succesfully</p>"
                + "<p>The attack report is provided in the following files: "
                + "<ul>"
                + "<li><a href='"
                + filenameMetadata
                + "'>Attack Summary</a></li>"
                + "<li><a href='"
                + filenameImgGraph
                + "'>Attackgraph via PNG</a></li>"
                + "<li><a href='"
                + filenameUntampered
                + "'>CSV-Dataset Untampered-Requests</a></li>"
                + "<li><a href='"
                + filenameTampered
                + "'>CSV-Dataset Tampered-Requests</a></li>"
                + "<li><a href='"
                + filenameTestprobe
                + "'>CSV-Dataset Testprobe-Requests</a></li>"
                + "</ul>"
                + "<p>compressed Version as zip <a href='"
                + filenameZip + "'>results.zip</a></p>" + "</body>" + "</html>";
        File file = new File( fullPath, filenameReport );
        FileWriter writer = new FileWriter( file );
        writer.append( htmlString );
        writer.flush();
        writer.close();
    }

    /*
     * Open Helpmenu in Browserwindow
     */
    public void openHelpmenu()
    {
        // create Folder / Paths
        String property = "java.io.tmpdir";
        String tempDir = System.getProperty( property );
        File resultDir = new File( tempDir + "/wsattackerdos" );
        if ( !resultDir.exists() )
        { // if the directory does not exist, create it
            resultDir.mkdir();
        }

        // copy Helpfile from .jar to resultDir
        URL inputUrl;
        inputUrl = getClass().getResource( "/HTML/help.html" );
        File dest = new File( resultDir + "/help.html" );
        URL inputUrl2;
        inputUrl2 = getClass().getResource( "/IMG/guiResult.png" );
        File dest2 = new File( resultDir + "/guiResult.png" );
        URL inputUrl3;
        inputUrl3 = getClass().getResource( "/IMG/architecture.png" );
        File dest3 = new File( resultDir + "/architecture.png" );
        try
        {
            FileUtils.copyURLToFile( inputUrl, dest );
            FileUtils.copyURLToFile( inputUrl2, dest2 );
            FileUtils.copyURLToFile( inputUrl3, dest3 );
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }

        // open in Browser
        File report = new File( resultDir, "help.html" );
        new OpenURI( report );
    }

}
