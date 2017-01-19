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
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.position.PositionIterator;
import wsattacker.library.intelligentdos.position.SchemaAnalyzerPositionIterator;
import wsattacker.library.intelligentdos.success.SimpleSuccessDecider;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.testhelper.IDoSTestHelper;
import wsattacker.testhelper.MetricOracle;
import wsattacker.testhelper.MetricOracleImpl.MetricOracleBuilder;

/**
 * @author Christian Altmeier
 */
public class IntelligentDoSSimpleBehaviorTest
{

    private static String xmlMessage =
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axis=\"http://axis2.wsattacker\">"
            + "   <soapenv:Header/>" + "   <soapenv:Body>" + "      <axis:reverser>" + "         <!--Optional:-->"
            + "         <axis:toReverse>?</axis:toReverse>" + "      </axis:reverser>" + "   </soapenv:Body>"
            + "</soapenv:Envelope>";

    // The SchemaAnalyzer
    private static final SchemaAnalyzer schemaAnalyzer =
        SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );

    private final PositionIterator positionIterator = new SchemaAnalyzerPositionIterator( schemaAnalyzer, xmlMessage );

    private final IntelligentDoSLibraryImpl impl = new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );

    @Before
    public void setUp()
    {
        // initialize
        impl.setSuccessDecider( new SimpleSuccessDecider() );

        impl.setServerRecoveryTime( 1000 );
        impl.initialize();
    }

    /**
     * this is a test where the library is executed against an service that is not reachable. For this test the default
     * behavior of the implementation is used. This means that all DoS Attacks are chosen and the predefined default
     * values for the separate attacks aren't changed
     */
    @Test
    public void serviceNotReachableTest()
    {
        MetricOracle notReachableOracle =
            MetricOracleBuilder.create().withCount( 24 ).withDuration( 0 ).withContent( "" ).build();

        // first attack to send (UTR)
        assertThat( impl.hasFurtherAttack(), is( true ) );
        AttackModel attackModel = impl.nextAttack();
        assertThat( attackModel.getRequestType(), is( RequestType.UNTAMPERED ) );
        assertThat( attackModel.getDoSAttack().getName(), is( "CoerciveParsing" ) );
        // no resopnse from the server
        notReachableOracle.createMetric( attackModel );
        impl.update( attackModel );

        // second attack to send (UTR+)
        assertThat( impl.hasFurtherAttack(), is( true ) );
        attackModel = impl.nextAttack();
        assertThat( attackModel.getServerRecoveryBeforeSend(), is( not( 0 ) ) );
        assertThat( attackModel.getRequestType(), is( RequestType.UNTAMPERED ) );
        // again no resopnse from the server
        notReachableOracle.createMetric( attackModel );
        impl.update( attackModel );

        // a verification
        assertThat( impl.hasFurtherAttack(), is( true ) );
        attackModel = impl.nextAttack();
        notReachableOracle.createMetric( attackModel );
        impl.update( attackModel );

        assertThat( impl.hasFurtherAttack(), is( false ) );
    }

    /**
     * this is a test where the web service is not vulnerable against any of the DoS Attacks. Because the test takes
     * very long it will be ignored
     */
    @Ignore
    public void notVulnerableTest()
    {
        MetricOracle notVulnerableOracle =
            MetricOracleBuilder.create().withCount( 24 ).withDuration( 1000 ).withContent( "OK" ).build();

        DoSAttack[] attacks = IntelligentDoSLibraryImpl.getAllAttacks();

        IDoSTestHelper.iterate( notVulnerableOracle, attacks, impl );

        assertThat( impl.hasFurtherAttack(), is( false ) );
        assertThat( impl.getSuccessfulAttacks().size(), is( 0 ) );
    }

    /**
     * this is a test where the web service is vulnerable against every of our DoS Attacks. Every PayloadPosition and
     * every position
     */
    @Test
    public void vulnerableTest()
    {
        MetricOracle vulnerableOracle =
            MetricOracleBuilder.create().withCount( 24 ).withDuration( 1000 ).withContent( "OK" ).withAllVulnerable( true ).build();

        DoSAttack[] attacks = IntelligentDoSLibraryImpl.getAllAttacks();

        IDoSTestHelper.iterate( vulnerableOracle, attacks, impl );

        assertThat( impl.hasFurtherAttack(), is( false ) );
        // CoerciveParsing: 3 ExtensionPoints
        // XmlElementCount: 3 ExtensionPoints
        // XmlAttributeCount: 3 ExtensionPoints * 2 PayloadPositions
        // XmlEntityExpansion: 3 ExtensionPoints
        // XmlExternalEntity: 3 ExtensionPoints
        // HashCollision: 3 ExtensionPoints * 3 CollisionGenerator
        // XmlOverlongNames: 3 ExtensionPoints * 3 Overlong
        // ---> 36
        assertThat( impl.getSuccessfulAttacks().size(), is( 36 ) );
    }

}
