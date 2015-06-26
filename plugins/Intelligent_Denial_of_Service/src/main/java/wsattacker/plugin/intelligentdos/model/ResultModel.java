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
package wsattacker.plugin.intelligentdos.model;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.CloseShieldInputStream;

import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.common.Threshold;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.success.SimpleSuccessDecider;
import wsattacker.library.intelligentdos.success.SuccessDecider;
import wsattacker.plugin.intelligentdos.persistence.AttackMetaDataJAXB;
import wsattacker.plugin.intelligentdos.persistence.SuccessfulAttackJAXB;

import com.google.common.collect.Lists;

/**
 * @author Christian Altmeier
 */
public class ResultModel
{
    private static final String FILENAME_METADATA = "metaData.xml";

    private static final String FILENAME_XML_PLACEHOLDER = "xmlWithPlaceholder.txt";

    private static final String FILENAME_TR_CONTENT = "tamperedContent.xml";

    private static final String FILENAME_URT_CONTENT = "untamperedContent.xml";

    private static final String FILENAME_UTR_DUR = "utrDurationInNano.csv";

    private static final String FILENAME_TR_DUR = "trDurationInNano.csv";

    private static final String FILENAME_TP_DUR = "tpDurationInNano.csv";

    private Date startDate;

    private Date stopDate;

    private List<SuccessfulAttack> attacks = Lists.newArrayList();

    private List<DoSAttack> notPossible = Lists.newArrayList();

    private List<Threshold> thresholds = Lists.newArrayList();

    private double maximumRequestsPerSecond;

    private static SuccessDecider successDecider = new SimpleSuccessDecider();

    public ResultModel()
    {
    }

    public ResultModel( List<SuccessfulAttack> attacks )
    {
        this.attacks = attacks;
    }

    public Date getStartDate()
    {
        if ( startDate != null )
        {
            return new Date( startDate.getTime() );
        }
        else
        {
            return null;
        }
    }

    public void setStartDate( Date startDate )
    {
        if ( startDate != null )
        {
            this.startDate = new Date( startDate.getTime() );
        }
        else
        {
            this.startDate = null;
        }
    }

    public Date getStopDate()
    {
        if ( stopDate != null )
        {
            return new Date( stopDate.getTime() );
        }
        else
        {
            return null;
        }
    }

    public void setStopDate( Date stopDate )
    {
        if ( stopDate != null )
        {
            this.stopDate = new Date( stopDate.getTime() );
        }
        else
        {
            this.stopDate = null;
        }
    }

    public long getAttackDurationInSeconds()
    {
        if ( startDate == null || stopDate == null )
        {
            return 0;
        }

        return ( stopDate.getTime() - startDate.getTime() ) / 1000;
    }

    public List<SuccessfulAttack> getAttacks()
    {
        return attacks;
    }

    public List<DoSAttack> getNotPossible()
    {
        return notPossible;
    }

    public void setNotPossible( List<DoSAttack> notPossibleList )
    {
        this.notPossible = notPossibleList;
    }

    public List<Threshold> getThresholds()
    {
        return thresholds;
    }

    public void setThresholds( List<Threshold> thresholds )
    {
        this.thresholds = thresholds;
    }

    public double getMaximumRequestsPerSecond()
    {
        return maximumRequestsPerSecond;
    }

    public void setMaximumRequestsPerSecond( double maximumRequestsPerSecond )
    {
        this.maximumRequestsPerSecond = maximumRequestsPerSecond;
    }

    public void save( File selectedFile )
        throws IOException
    {
        // Wrap a FileOutputStream around a ZipOutputStream
        // to store the zip stream to a file. Note that this is
        // not absolutely necessary
        FileOutputStream fileOutputStream = new FileOutputStream( selectedFile );
        ZipOutputStream zipOutputStream = new ZipOutputStream( fileOutputStream );
        try
        {
            createAttackMetaData( zipOutputStream, FILENAME_METADATA );
        }
        catch ( JAXBException e )
        {
            throw new IOException( e );
        }

        int index = 1;
        for ( SuccessfulAttack sa : attacks )
        {
            // a ZipEntry represents a file entry in the zip archive
            ZipEntry zipEntry = new ZipEntry( sa.getDoSAttack().getName() + "_a" + index + ".zip" );
            zipOutputStream.putNextEntry( zipEntry );

            ZipOutputStream innerZipOutputStream = new ZipOutputStream( zipOutputStream );
            try
            {
                persistSA( sa, innerZipOutputStream );
            }
            catch ( JAXBException e )
            {
                throw new IOException( e );
            }
            innerZipOutputStream.finish();

            // close ZipEntry to store the stream to the file
            zipOutputStream.closeEntry();
            index++;
        }

        zipOutputStream.close();
        fileOutputStream.close();
    }

    public void readIn( File file )
    {
        attacks = Lists.newArrayList();

        ZipInputStream stream = null;
        try
        {
            stream = new ZipInputStream( new FileInputStream( file ) );

            ZipEntry entry;
            while ( ( entry = stream.getNextEntry() ) != null )
            {
                if ( FILENAME_METADATA.equals( entry.getName() ) )
                {
                    // create JAXB context and instantiate marshaller
                    JAXBContext context = JAXBContext.newInstance( AttackMetaDataJAXB.class );
                    Unmarshaller um = context.createUnmarshaller();
                    AttackMetaDataJAXB amjaxb =
                        (AttackMetaDataJAXB) um.unmarshal( new CloseShieldInputStream( stream ) );

                    ResultModel r = amjaxb.toResultModel();
                    setStartDate( r.getStartDate() );
                    setStopDate( r.getStopDate() );
                    setMaximumRequestsPerSecond( r.getMaximumRequestsPerSecond() );
                    setNotPossible( r.getNotPossible() );
                    setThresholds( r.getThresholds() );
                }
                else
                {
                    attacks.add( readIn( stream ) );
                }
            }
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        catch ( JAXBException e )
        {
            e.printStackTrace();
        }
        finally
        {
            if ( stream != null )
            {
                try
                {
                    stream.close();
                }
                catch ( IOException e )
                {
                    // ignore
                }
            }
        }
    }

    private void persistSA( SuccessfulAttack sa, ZipOutputStream zipOutputStream )
        throws IOException, JAXBException
    {
        createMetaData( zipOutputStream, FILENAME_METADATA, sa );

        createXMLContentEntry( zipOutputStream, FILENAME_XML_PLACEHOLDER, sa.getXmlWithPlaceholder() );
        // untampered
        createMetricEntry( zipOutputStream, FILENAME_UTR_DUR, sa.getUntamperedMetrics() );
        createXMLContentEntry( zipOutputStream, FILENAME_URT_CONTENT, sa.getUntamperedContent() );
        // tampered
        createMetricEntry( zipOutputStream, FILENAME_TR_DUR, sa.getTamperedMetrics() );
        createXMLContentEntry( zipOutputStream, FILENAME_TR_CONTENT, sa.getTamperedContent() );
        // test probes
        createMetricEntry( zipOutputStream, FILENAME_TP_DUR, sa.getTestProbes() );
    }

    private void createAttackMetaData( ZipOutputStream zipOutputStream, String name )
        throws IOException, JAXBException
    {

        // a ZipEntry represents a file entry in the zip archive
        ZipEntry zipEntry = new ZipEntry( name );
        zipOutputStream.putNextEntry( zipEntry );

        // create JAXB context and instantiate marshaller
        JAXBContext context = JAXBContext.newInstance( AttackMetaDataJAXB.class );
        Marshaller m = context.createMarshaller();
        m.setProperty( Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE );

        // Write to stream
        AttackMetaDataJAXB fromResultModel = AttackMetaDataJAXB.fromResultModel( this );
        m.marshal( fromResultModel, zipOutputStream );

        // close ZipEntry to store the stream to the file
        zipOutputStream.closeEntry();
    }

    private void createMetaData( ZipOutputStream zipOutputStream, String name, SuccessfulAttack successfulAttack )
        throws IOException, JAXBException
    {
        // a ZipEntry represents a file entry in the zip archive
        ZipEntry zipEntry = new ZipEntry( name );
        zipOutputStream.putNextEntry( zipEntry );

        // create JAXB context and instantiate marshaller
        JAXBContext context = JAXBContext.newInstance( SuccessfulAttackJAXB.class );
        Marshaller m = context.createMarshaller();
        m.setProperty( Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE );

        // Write to stream
        SuccessfulAttackJAXB fromAttackModel = SuccessfulAttackJAXB.fromAttackModel( successfulAttack );
        m.marshal( fromAttackModel, zipOutputStream );

        // close ZipEntry to store the stream to the file
        zipOutputStream.closeEntry();
    }

    private void createXMLContentEntry( ZipOutputStream zipOutputStream, String name, String requestContent )
        throws IOException
    {
        // a ZipEntry represents a file entry in the zip archive
        // We name the ZipEntry after the original file's name
        ZipEntry zipEntry = new ZipEntry( name );
        zipOutputStream.putNextEntry( zipEntry );

        zipOutputStream.write( requestContent.getBytes( Charset.defaultCharset() ) );

        // close ZipEntry to store the stream to the file
        zipOutputStream.closeEntry();

    }

    private void createMetricEntry( ZipOutputStream zipOutputStream, String name, List<Metric> metrics )
        throws IOException
    {
        // a ZipEntry represents a file entry in the zip archive
        // We name the ZipEntry after the original file's name
        ZipEntry zipEntry = new ZipEntry( name );
        zipOutputStream.putNextEntry( zipEntry );

        int count = 0;
        for ( Metric metric : metrics )
        {
            if ( count++ != 0 )
            {
                zipOutputStream.write( '\n' );
            }
            zipOutputStream.write( String.valueOf( metric.getDuration() ).getBytes( Charset.defaultCharset() ) );
        }

        // close ZipEntry to store the stream to the file
        zipOutputStream.closeEntry();
    }

    private SuccessfulAttack readIn( ZipInputStream stream )
        throws IOException, JAXBException
    {
        ZipInputStream inputStream = new ZipInputStream( stream );

        SuccessfulAttack sa = null;
        String xmlWithPlaceholder = "";
        String utrContent = "";
        String trContent = "";
        List<Metric> utrMetrics = Lists.newArrayList();
        List<Metric> trMetrics = Lists.newArrayList();
        List<Metric> tpMetrics = Lists.newArrayList();
        ZipEntry entry;
        while ( ( entry = inputStream.getNextEntry() ) != null )
        {
            if ( FILENAME_METADATA.equals( entry.getName() ) )
            {
                // create JAXB context and instantiate marshaller
                JAXBContext context = JAXBContext.newInstance( SuccessfulAttackJAXB.class );
                Unmarshaller um = context.createUnmarshaller();
                SuccessfulAttackJAXB amjaxb =
                    (SuccessfulAttackJAXB) um.unmarshal( new CloseShieldInputStream( inputStream ) );

                sa = amjaxb.toSuccessfulAttack();
            }
            else if ( FILENAME_UTR_DUR.equals( entry.getName() ) )
            {
                utrMetrics = streamToMetric( inputStream );
            }
            else if ( FILENAME_TR_DUR.equals( entry.getName() ) )
            {
                trMetrics = streamToMetric( inputStream );
            }
            else if ( FILENAME_TP_DUR.equals( entry.getName() ) )
            {
                tpMetrics = streamToMetric( inputStream );
            }
            else if ( FILENAME_XML_PLACEHOLDER.equals( entry.getName() ) )
            {
                xmlWithPlaceholder = IOUtils.toString( inputStream );
            }
            else if ( FILENAME_URT_CONTENT.equals( entry.getName() ) )
            {
                utrContent = IOUtils.toString( inputStream );
            }
            else if ( FILENAME_TR_CONTENT.equals( entry.getName() ) )
            {
                trContent = IOUtils.toString( inputStream );
            }
            else
            {
                // nothing to do
            }
        }

        if ( sa != null )
        {
            sa.setXmlWithPlaceholder( xmlWithPlaceholder );
            sa.setUntamperedContent( utrContent );
            sa.setTamperedContent( trContent );
            Long[] run1 = new Long[utrMetrics.size()];
            Long[] run2 = new Long[trMetrics.size()];

            int index = 0;
            for ( Metric metric : utrMetrics )
            {
                sa.getUntamperedMetrics().add( metric );
                run1[index++] = metric.getDuration();
            }

            index = 0;
            for ( Metric metric : trMetrics )
            {
                sa.getTamperedMetrics().add( metric );
                run2[index++] = metric.getDuration();
            }

            for ( Metric metric : tpMetrics )
            {
                sa.getTestProbeMetrics().add( metric );
            }

            sa.setEfficiency( successDecider.getEfficency( run1, run2 ) );
            sa.setRatio( successDecider.calculateRatio( run1, run2 ) );
        }

        return sa;
    }

    private static List<Metric> streamToMetric( ZipInputStream inputStream )
        throws IOException
    {
        List<Metric> list = new ArrayList<Metric>();

        BufferedReader reader = new BufferedReader( new InputStreamReader( inputStream, Charset.defaultCharset() ) );

        String data = null;
        while ( ( data = reader.readLine() ) != null )
        {
            try
            {
                long parseLong = Long.parseLong( data.split( "," )[0] );
                Metric metric = new Metric();
                metric.setDuration( parseLong );
                list.add( metric );
            }
            catch ( NumberFormatException e )
            {
                e.printStackTrace();
            }
        }

        // we may not close

        return list;
    }

}
