/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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

package wsattacker.library.xmlencryptionattack.avoidingengine;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import static wsattacker.library.signatureWrapping.util.signature.ReferenceElement.LOG;
import wsattacker.library.signatureWrapping.xpath.wrapping.WrappingOracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.EncSigWrappingOracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.EncryptionWrappingOracle;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectionManager;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.FactoryFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.Pipeline;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class AvoidingManagerTest
{

    public static Logger log;

    public static SchemaAnalyzer schemaAnalyser;

    public AvoidingManagerTest()
    {

    }

    @BeforeClass
    public static void setUpBeforeClass()
        throws Exception
    {
        // Logger
        log = Logger.getLogger( WrappingOracle.class );
        Logger.getLogger( "wsattacker.plugin.signaturewrapping.util.signature" ).setLevel( Level.ALL );
        Logger.getLogger( "wsattacker.plugin.signaturewrapping.test.util" ).setLevel( Level.ALL );
        Logger.getLogger( WrappingOracle.class ).setLevel( Level.ALL );
        Logger.getLogger( "wsattacker.library.signatureWrapping.xpath.weakness.XPathDescendantWeakness" ).setLevel( Level.ALL );
        Logger.getLogger( "wsattacker.library.schemaanalyzer.SchemaAnalyzerImpl" ).setLevel( Level.ALL );
        Logger.getLogger( "wsattacker.plugin.signaturewrapping.util.wrapping" ).setLevel( Level.TRACE );

        LOG.setLevel( Level.ALL );
        Logger.getLogger( "wsattacker.plugin.signatureWrapping.schema.SchemaAnalyser" ).setLevel( Level.ALL );

        // Load Schema Files
        schemaAnalyser = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );
    }

    @AfterClass
    public static void tearDownClass()
    {
    }

    @Before
    public void setUp()
    {
    }

    @After
    public void tearDown()
    {
    }

    @Test
    public void testSomething()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException,
        InvalidWeaknessException
    {
        DetectionManager detectManager = null;
        DetectionReport detectReport = null;
        EncryptionInfo encInfo = null;
        Pipeline pipeLine = null;
        EncSigWrappingOracle encSigWrappOracle = null;
        EncryptionWrappingOracle encWrappOracle = null;
        Document rawFile = null;
        Document possAvoidedDoc = null;
        int max = 0;

        rawFile = DomUtilities.readDocument( "src/test/resources/case_encKey_encData_signed.xml" );
        pipeLine = new Pipeline();
        pipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.ENCRYPTIONFILTER ) );
        pipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.SIGNATUREFILTER ) );
        detectManager = new DetectionManager( pipeLine, rawFile );
        detectManager.startDetection();
        detectReport = detectManager.getDetectionReport();
        encInfo = ( (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER ) );
        AbstractEncryptionElement encEl =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();

        List<Payload> pays =
            ( (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER ) ).getSignatureManager().getPayloads();
        for ( int i = 0; pays.size() > i; i++ )
        {
            pays.get( i ).setValue( pays.get( i ).getValue() );
            ElementAttackProperties attackProps = encEl.getAttackProperties();
            attackProps.setWrappingPayloadElement( encEl.getEncryptedElement() );
        }

        encSigWrappOracle =
            new EncSigWrappingOracle( encInfo.getEncryptedKeyElements().get( 0 ), detectReport, schemaAnalyser );
        encWrappOracle =
            new EncryptionWrappingOracle( encInfo.getEncryptedKeyElements().get( 0 ), detectReport, schemaAnalyser );

        max = encSigWrappOracle.maxPossibilities();

        for ( int i = 0; max > i; i++ )
        {
            possAvoidedDoc = encSigWrappOracle.getPossibility( i );
        }

        /*
         * max = encWrappOracle.maxPossibilities(); System.out.println(max); for(int i = 0;max>i;i++) {
         * //System.out.println(max); possAvoidedDoc = encWrappOracle.getPossibility(i);
         * System.out.println(domToString(possAvoidedDoc)); }
         */

    }

}
