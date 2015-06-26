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
package wsattacker.library.intelligentdos;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;
import java.util.Set;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.common.Threshold;
import wsattacker.library.intelligentdos.dos.CoerciveParsing;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.dos.HashCollision;
import wsattacker.library.intelligentdos.dos.XmlAttributeCount;
import wsattacker.library.intelligentdos.dos.XmlElementCount;
import wsattacker.library.intelligentdos.dos.XmlEntityExpansion;
import wsattacker.library.intelligentdos.dos.XmlExternalEntity;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.library.intelligentdos.helper.IterateModel.IterateStrategie;
import wsattacker.library.intelligentdos.position.AnyElementPosition;
import wsattacker.library.intelligentdos.position.MatcherPositionIterator;
import wsattacker.library.intelligentdos.position.PositionIterator;
import wsattacker.library.intelligentdos.position.SchemaAnalyzerPositionIterator;
import wsattacker.library.intelligentdos.success.SimpleSuccessDecider;
import wsattacker.library.schemaanalyzer.AnyElementProperties;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.testhelper.IDoSTestHelper;
import wsattacker.testhelper.MetricOracle;
import wsattacker.testhelper.MetricOracleImpl.MetricOracleBuilder;
import wsattacker.testhelper.RecordedMetricOracle;
import wsattacker.testhelper.SABuilder;

import com.google.common.collect.Lists;

/**
 * @author Christian Altmeier
 */
public class IntelligentDoSBehaviorTest
{

    private static String xmlMessage =
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axis=\"http://axis2.wsattacker\">"
            + "   <soapenv:Header/>" + "   <soapenv:Body>" + "      <axis:reverser>" + "         <!--Optional:-->"
            + "         <axis:toReverse>?</axis:toReverse>" + "      </axis:reverser>" + "   </soapenv:Body>"
            + "</soapenv:Envelope>";

    // The SchemaAnalyzer
    private static final SchemaAnalyzer schemaAnalyzer =
        SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );

    private static List<AnyElementProperties> expansionPoints;

    //
    private final PositionIterator positionIterator = new SchemaAnalyzerPositionIterator( schemaAnalyzer, xmlMessage );

    @BeforeClass
    public static void setUpBefore()
    {

        try
        {
            Document toAnalyze = DomUtilities.stringToDom( xmlMessage );
            Set<AnyElementProperties> findExpansionPoint =
                schemaAnalyzer.findExpansionPoint( toAnalyze.getDocumentElement() );
            expansionPoints = Lists.newArrayList( findExpansionPoint );
        }
        catch ( SAXException e )
        {
            e.printStackTrace();
        }

    }

    /**
     * In this test we simulate that one attack is successful. In this case CoersiveParsing at header position with 2500
     * tags. We reduce the count of possible DoS Attacks, otherwise the test takes a lot of time
     */
    @Test
    public void vulOneTest()
    {
        AnyElementPosition position = new AnyElementPosition( xmlMessage, expansionPoints.get( 1 ) );

        SuccessfulAttack successfulAttack =
            SABuilder.CoerciveParsing( 2500 ).withPayloadPosition( PayloadPosition.ELEMENT ).withPosition( position ).withParamItem( new CommonParamItem(
                                                                                                                                                          32,
                                                                                                                                                          16,
                                                                                                                                                          1000 ) ).build();

        MetricOracle vulnerableOracle =
            MetricOracleBuilder.create().withCount( 24 ).withDuration( 1000 ).withContent( "OK" ).withVulnerable( successfulAttack ).build();

        CoerciveParsing coerciveParsing = new CoerciveParsing();
        // four values: 1000 / 2000 / 3000 / 4000
        IterateModel iterateModel = IterateModel.custom().startAt( 1000 ).stopAt( 4000 ).setIncrement( 1000 ).build();
        coerciveParsing.setNumberOfTagsIterator( iterateModel );

        DoSAttack[] attacks = new DoSAttack[] { coerciveParsing, new XmlElementCount(), new XmlExternalEntity() };

        IntelligentDoSLibraryImpl impl = new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );
        impl.setAttacks( attacks );

        // initialize
        impl.setSuccessDecider( new SimpleSuccessDecider() );

        impl.setServerRecoveryTime( 1000 );
        impl.initialize();

        IDoSTestHelper.iterate( vulnerableOracle, attacks, impl );

        assertThat( impl.hasFurtherAttack(), is( false ) );
        List<SuccessfulAttack> successfulAttacks = impl.getSuccessfulAttacks();
        assertThat( successfulAttacks.size(), is( 1 ) );
        SuccessfulAttack verify = successfulAttacks.get( 0 );
        assertThat( verify.getDoSAttack().getName(), is( "CoerciveParsing" ) );
        assertThat( verify.getDoSAttack().getCurrentParams().get( 0 ).getValueAsString(), is( "3000" ) );
        assertThat( verify.getPayloadPosition(), is( PayloadPosition.ELEMENT ) );
        assertTrue( verify.getPosition().equals( position ) );
        assertThat( verify.getParamItem().getNumberOfRequests(), is( 128 ) );
        assertThat( verify.getParamItem().getNumberOfThreads(), is( 8 ) );
        assertThat( verify.getParamItem().getMilliesBetweenRequests(), is( 250 ) );
    }

    /**
     * In this test we simulate that two attack are successful. In this case CoersiveParsing at header position with
     * 2500 tags and XmlElementCount with 50000 elements at the same position. We reduce the count of possible DoS
     * Attacks, otherwise the test takes a lot of time
     */
    @Test
    public void vulnerableAgainstTwoAttacksTest()
    {
        AnyElementPosition position = new AnyElementPosition( xmlMessage, expansionPoints.get( 1 ) );

        SuccessfulAttack[] attacksArray = new SuccessfulAttack[2];
        attacksArray[0] =
            SABuilder.CoerciveParsing( 2500 ).withPayloadPosition( PayloadPosition.ELEMENT ).withPosition( position ).withParamItem( new CommonParamItem(
                                                                                                                                                          32,
                                                                                                                                                          16,
                                                                                                                                                          1000 ) ).build();
        attacksArray[1] =
            SABuilder.XmlElementCount( (int) ( 12500 * 3.5 ) ).withPayloadPosition( PayloadPosition.ELEMENT ).withPosition( position ).withParamItem( new CommonParamItem(
                                                                                                                                                                           32,
                                                                                                                                                                           16,
                                                                                                                                                                           1000 ) ).build();

        MetricOracle vulnerableOracle =
            MetricOracleBuilder.create().withCount( 24 ).withDuration( 1000 ).withContent( "OK" ).withVulnerable( attacksArray ).build();

        CoerciveParsing coerciveParsing = new CoerciveParsing();
        // four values: 1000 / 2000 / 3000 / 4000
        IterateModel iterateModel = IterateModel.custom().startAt( 1000 ).stopAt( 4000 ).setIncrement( 1000 ).build();
        coerciveParsing.setNumberOfTagsIterator( iterateModel );

        DoSAttack[] attacks = new DoSAttack[] { new XmlExternalEntity(), coerciveParsing, new XmlElementCount() };

        IntelligentDoSLibraryImpl impl = new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );
        impl.setAttacks( attacks );

        // initialize
        impl.setSuccessDecider( new SimpleSuccessDecider() );

        impl.setServerRecoveryTime( 1000 );
        impl.initialize();

        IDoSTestHelper.iterate( vulnerableOracle, attacks, impl );

        assertThat( impl.hasFurtherAttack(), is( false ) );
        List<SuccessfulAttack> successfulAttacks = impl.getSuccessfulAttacks();
        assertThat( successfulAttacks.size(), is( 2 ) );

        // CoerciveParsing
        SuccessfulAttack verify = successfulAttacks.get( 0 );
        assertThat( verify.getDoSAttack().getName(), is( "CoerciveParsing" ) );
        assertThat( verify.getDoSAttack().getCurrentParams().get( 0 ).getValueAsString(), is( "3000" ) );
        assertThat( verify.getPayloadPosition(), is( PayloadPosition.ELEMENT ) );
        assertTrue( verify.getPosition().equals( position ) );
        assertThat( verify.getParamItem().getNumberOfRequests(), is( 128 ) );
        assertThat( verify.getParamItem().getNumberOfThreads(), is( 8 ) );
        assertThat( verify.getParamItem().getMilliesBetweenRequests(), is( 250 ) );

        // XmlElementCount
        verify = successfulAttacks.get( 1 );
        assertThat( verify.getDoSAttack().getName(), is( "XmlElementCount" ) );
        assertThat( verify.getDoSAttack().getCurrentParams().get( 0 ).getValueAsString(), is( "50000" ) );
        assertThat( verify.getPayloadPosition(), is( PayloadPosition.ELEMENT ) );
        assertTrue( verify.getPosition().equals( position ) );
        assertThat( verify.getParamItem().getNumberOfRequests(), is( 128 ) );
        assertThat( verify.getParamItem().getNumberOfThreads(), is( 8 ) );
        assertThat( verify.getParamItem().getMilliesBetweenRequests(), is( 250 ) );
    }

    @Test
    public void simpleThresholdTest()
    {
        DoSAttack minimum = SABuilder.XmlAttributeCount( 10001, "a" ).build().getDoSAttack();
        Threshold threshold = new Threshold( minimum, minimum );

        Threshold[] thresholdArray = { threshold };
        MetricOracle vulnerableOracle =
            MetricOracleBuilder.create().withCount( 24 ).withDuration( 1000 ).withContent( "OK" ).withThreshold( thresholdArray ).build();

        XmlAttributeCount xmlAttributeCount = new XmlAttributeCount();
        xmlAttributeCount.setNumberOfAttributesIterator( IterateModel.custom().startAt( 3072 ).stopAt( 960000 ).setIncrement( 4 ).setIterateStrategie( IterateStrategie.MUL ).build() );
        XmlElementCount xmlElementCount = new XmlElementCount();
        DoSAttack[] attacks = new DoSAttack[] { xmlAttributeCount, xmlElementCount };

        IntelligentDoSLibraryImpl impl = new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );
        impl.setAttacks( attacks );

        // initialize
        impl.setSuccessDecider( new SimpleSuccessDecider() );

        impl.setServerRecoveryTime( 1000 );
        impl.initialize();

        IDoSTestHelper.iterate( vulnerableOracle, attacks, impl );

        List<Threshold> thList = impl.getThresholds();
        assertThat( thList.size(), is( 1 ) );
        Threshold th = thList.get( 0 );
        assertThat( th.getMinimum().getCurrentParams().get( 0 ).getValueAsString(), is( "9984" ) );
        assertThat( th.getMaximum().getCurrentParams().get( 0 ).getValueAsString(), is( "10368" ) );
    }

    @Test
    public void thresholdTest()
    {
        DoSAttack minimum = SABuilder.XmlAttributeCount( 10001, "a" ).build().getDoSAttack();
        Threshold threshold = new Threshold( minimum, minimum );

        Threshold[] thresholdArray = { threshold };
        MetricOracle vulnerableOracle =
            MetricOracleBuilder.create().withCount( 24 ).withDuration( 1000 ).withContent( "OK" ).withThreshold( thresholdArray ).withMaxRequestsPerSecond( 15 ).build();

        XmlAttributeCount xmlAttributeCount = new XmlAttributeCount();
        xmlAttributeCount.setNumberOfAttributesIterator( IterateModel.custom().startAt( 3072 ).stopAt( 960000 ).setIncrement( 4 ).setIterateStrategie( IterateStrategie.MUL ).build() );
        XmlElementCount xmlElementCount = new XmlElementCount();
        DoSAttack[] attacks = new DoSAttack[] { xmlAttributeCount, xmlElementCount };

        IntelligentDoSLibraryImpl impl = new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );
        impl.setAttacks( attacks );

        // initialize
        impl.setSuccessDecider( new SimpleSuccessDecider() );

        impl.setServerRecoveryTime( 1000 );
        impl.initialize();

        IDoSTestHelper.iterate( vulnerableOracle, attacks, impl );

        List<Threshold> thList = impl.getThresholds();
        assertThat( thList.size(), is( 1 ) );
        Threshold th = thList.get( 0 );
        assertThat( th.getMinimum().getCurrentParams().get( 0 ).getValueAsString(), is( "9984" ) );
        assertThat( th.getMaximum().getCurrentParams().get( 0 ).getValueAsString(), is( "10368" ) );
    }
    
    @Test
    public void maxDocumentSizeTest()
    {
    	int maxDocumentSize = 4 * 1024; // 4 KB
		MetricOracle vulnerableOracle =
                MetricOracleBuilder.create().withCount( 24 ).withDuration( 1000 ).withContent( "OK" ).withMaxDocumentSize(maxDocumentSize).build();
    	
    	HashCollision hashCollision = new HashCollision();
    	
    	DoSAttack[] attacks = new DoSAttack[] { hashCollision };
    	
    	IntelligentDoSLibraryImpl impl = new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );
        impl.setAttacks( attacks );

        // initialize
        impl.setSuccessDecider( new SimpleSuccessDecider() );

        impl.setServerRecoveryTime( 1000 );
        impl.initialize();

        IDoSTestHelper.iterate( vulnerableOracle, attacks, impl );
        
        List<Threshold> thList = impl.getThresholds();
        assertThat( thList.size(), is( 1 ) );
    }

    @Ignore
    public void recorded()
    {
        String xml =
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axis=\"http://axisversion.sample\" $$PAYLOADATTR$$>"
                + "<soapenv:Header $$PAYLOADATTR$$ />"
                + "<soapenv:Body $$PAYLOADATTR$$>"
                + "<axis:getVersion/>"
                + "$$PAYLOADELEMENT$$</soapenv:Body>" + "</soapenv:Envelope>";

        PositionIterator positionIterator = new MatcherPositionIterator( xml );

        // URL resource = getClass().getResource( "/2014-09-02_wsa" );
        // File folder = new File( resource.getFile() );
        File folder = new File( "d:\\wsa" );
        MetricOracle recordedOracle = new RecordedMetricOracle( folder );

        IntelligentDoSLibraryImpl impl = new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );
        DoSAttack[] attacks = { new XmlExternalEntity(), new XmlEntityExpansion(), new CoerciveParsing() };
        impl.setAttacks( attacks );

        // initialize
        impl.setSuccessDecider( new SimpleSuccessDecider() );

        impl.setServerRecoveryTime( 1000 );
        impl.initialize();

        IDoSTestHelper.iterate( recordedOracle, attacks, impl );

        assertThat( impl.getSuccessfulAttacks().size(), is( 12 ) );
    }

}
