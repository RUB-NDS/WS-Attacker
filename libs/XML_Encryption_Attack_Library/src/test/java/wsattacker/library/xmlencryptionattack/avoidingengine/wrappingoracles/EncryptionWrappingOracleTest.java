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

package wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles;

import java.util.List;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptedKeyRefWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptionAttributeIdWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptionSchemaWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.FactoryWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.WeaknessType;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectionManager;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.FactoryFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.Pipeline;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete.AvoidedDocErrorFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.CipherValueElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.ENC_TYPE_CONTENT;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.ENC_TYPE_ELEMENT;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;

/**
 * @author Dennis
 */
public class EncryptionWrappingOracleTest
{
    private static SchemaAnalyzer m_SchemaAnalyser;

    private static Logger log;

    private DetectionManager m_DetectManager = null;

    private Pipeline m_PipeLine = null;

    private EncryptionWrappingOracle m_EncWrappOracle = null;

    private Document m_RawFile = null;

    private SignatureManager m_SigManager;

    public EncryptionWrappingOracleTest()
    {
        m_PipeLine = new Pipeline();
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.ENCRYPTIONFILTER ) );
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.SIGNATUREFILTER ) );
        Logger.getLogger( EncryptedKeyRefWeakness.class ).setLevel( Level.OFF );
        Logger.getLogger( EncryptionAttributeIdWeakness.class ).setLevel( Level.OFF );
        Logger.getLogger( EncryptionSchemaWeakness.class ).setLevel( Level.OFF );
    }

    @BeforeClass
    public static void setUpClass()
    {
        // log = Logger.getLogger(EncryptionWrappingOracle.class);
        // Logger.getLogger("wsattacker.plugin.signaturewrapping.util.signature").setLevel(Level.WARN);
        // Logger.getLogger("wsattacker.plugin.signaturewrapping.test.util").setLevel(Level.WARN);
        // Logger.getLogger(DomUtilities.class).setLevel(Level.WARN);
        // ogger.getLogger(EncryptionWrappingOracle.class).setLevel(Level.WARN);
        // Logger.getLogger("wsattacker.plugin.signatureWrapping.schema.SchemaAnalyser").setLevel(Level.ALL);

        // Load Schema Files
        m_SchemaAnalyser = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );
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
    public void testEncKeyEncDataSignedWrapping()
        throws Exception
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/schema_encKey_encData_sig.xml" );
        Document possAvoidedDoc = null;
        int max = 0;
        String attackContent = "ENCRYPTED ATTACK PAYLOAD";
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );
        EncryptedKeyElement encKey = encInfo.getEncryptedKeyElements().get( 0 );
        AbstractEncryptionElement encEl =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();
        EncryptedDataElement encDataPay =
            new EncryptedDataElement( (Element) encEl.getEncryptedElement().cloneNode( true ) );
        ( (CipherValueElement) encDataPay.getCipherDataChild() ).setEncryptedData( attackContent );
        ElementAttackProperties attackProps = encEl.getAttackProperties();
        attackProps.setWrappingPayloadElement( encDataPay.getEncryptedElement() );

        assertFalse( encDataPay.getCipherDataChild().getEncryptedData().equals( encEl.getCipherDataChild().getEncryptedData() ) );

        m_EncWrappOracle = new EncryptionWrappingOracle( encKey, detectReport, m_SchemaAnalyser );
        max = m_EncWrappOracle.maxPossibilities();
        assertTrue( 0 < max );
        for ( int i = 0; max > i; i++ )
        {
            possAvoidedDoc = m_EncWrappOracle.getPossibility( i );
            List<Element> matchedData =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matchedData.size() );
            List<Element> matchedKey =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedKey", URI_NS_ENC, true );
            assertEquals( 1, matchedKey.size() );
            String attackDocString = domToString( possAvoidedDoc );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encEl.getCipherDataChild().getEncryptedData() ) );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ), attackDocString.contains( attackContent ) );
            // System.out.println(attackDocString);
            // references?
        }

    }

    @Test
    public void testSignedEncKeyWithSignedEncDataWrapping()
        throws Exception
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/schema_encKey_sig_encData_sig.xml" );
        Document possAvoidedDoc = null;
        int max = 0;
        String attackContentData = "ENCRYPTED ATTACK PAYLOAD DATA";
        String attackContentKey = "ENCRYPTED ATTACK PAYLOAD KEY";
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 2, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );
        assertEquals( "EncryptedKey", m_SigManager.getPayloads().get( 1 ).getSignedElement().getLocalName() );
        EncryptedKeyElement encKey = encInfo.getEncryptedKeyElements().get( 0 );
        AbstractEncryptionElement encEl =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();
        EncryptedDataElement encDataPay =
            new EncryptedDataElement( (Element) encEl.getEncryptedElement().cloneNode( true ) );
        ( (CipherValueElement) encDataPay.getCipherDataChild() ).setEncryptedData( attackContentData );

        EncryptedKeyElement encKeyPay =
            new EncryptedKeyElement( (Element) encKey.getEncryptedElement().cloneNode( true ) );
        ( (CipherValueElement) encKeyPay.getCipherDataChild() ).setEncryptedData( attackContentKey );
        ElementAttackProperties attackPropsData = encEl.getAttackProperties();
        ElementAttackProperties attackPropsKey = encKey.getAttackProperties();
        attackPropsData.setWrappingPayloadElement( encDataPay.getEncryptedElement() );
        attackPropsKey.setWrappingPayloadElement( encKeyPay.getEncryptedElement() );

        assertFalse( encDataPay.getCipherDataChild().getEncryptedData().equals( encEl.getCipherDataChild().getEncryptedData() ) );
        assertFalse( encKeyPay.getCipherDataChild().getEncryptedData().equals( encKey.getCipherDataChild().getEncryptedData() ) );

        m_EncWrappOracle = new EncryptionWrappingOracle( encKey, detectReport, m_SchemaAnalyser );
        max = m_EncWrappOracle.maxPossibilities();
        assertTrue( 0 < max );

        // test too long, but works
        /*
         * for(int i = 0;max>i;i++) { possAvoidedDoc = m_EncWrappOracle.getPossibility(i); List<Element> matchedData =
         * (List<Element>) DomUtilities.findChildren(possAvoidedDoc, "EncryptedData", URI_NS_ENC, true); assertEquals(2,
         * matchedData.size()); List<Element> matchedKey = (List<Element>) DomUtilities.findChildren(possAvoidedDoc,
         * "EncryptedKey", URI_NS_ENC, true); assertEquals(2, matchedKey.size()); String attackDocString =
         * domToString(possAvoidedDoc); assertTrue("Invalid Message:\n" + domToString(possAvoidedDoc),
         * attackDocString.contains(encEl.getCipherDataChild().getEncryptedData())); assertTrue("Invalid Message:\n" +
         * domToString(possAvoidedDoc), attackDocString.contains(attackContentData)); assertTrue("Invalid Message:\n" +
         * domToString(possAvoidedDoc), attackDocString.contains(encKey.getCipherDataChild().getEncryptedData()));
         * assertTrue("Invalid Message:\n" + domToString(possAvoidedDoc), attackDocString.contains(attackContentKey));
         * //System.out.println(attackDocString); //references? }
         */
    }

    @Test
    public void testSignedEncKeyWithEncDataWrapping()
        throws Exception
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_signed_encData.xml" );
        Document possAvoidedDoc = null;
        int max = 0;
        String attackContentKey = "ENCRYPTED ATTACK PAYLOAD KEY";
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "EncryptedKey", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );
        EncryptedKeyElement encKey = encInfo.getEncryptedKeyElements().get( 0 );

        EncryptedKeyElement encKeyPay =
            new EncryptedKeyElement( (Element) encKey.getEncryptedElement().cloneNode( true ) );
        ( (CipherValueElement) encKeyPay.getCipherDataChild() ).setEncryptedData( attackContentKey );
        ElementAttackProperties attackPropsKey = encKey.getAttackProperties();
        attackPropsKey.setWrappingPayloadElement( encKeyPay.getEncryptedElement() );
        assertFalse( encKeyPay.getCipherDataChild().getEncryptedData().equals( encKey.getCipherDataChild().getEncryptedData() ) );

        m_EncWrappOracle = new EncryptionWrappingOracle( encKey, detectReport, m_SchemaAnalyser );
        max = m_EncWrappOracle.maxPossibilities();
        assertTrue( 0 < max );
        for ( int i = 0; max > i; i++ )
        {
            possAvoidedDoc = m_EncWrappOracle.getPossibility( i );
            List<Element> matchedData =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 1, matchedData.size() );
            List<Element> matchedKey =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedKey", URI_NS_ENC, true );
            assertEquals( 2, matchedKey.size() );
            String attackDocString = domToString( possAvoidedDoc );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encKey.getCipherDataChild().getEncryptedData() ) );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( attackContentKey ) );
            // System.out.println(attackDocString);
            // references?
        }
    }

    @Test
    public void testEncKeyElementInSignedEncDataWrapping()
        throws Exception
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_inside_encData_signed.xml" );
        Document possAvoidedDoc = null;
        int max = 0;
        String attackContentKey = "ENCRYPTED ATTACK PAYLOAD KEY";
        String attackContentData = "ENCRYPTED ATTACK PAYLOAD DATA";
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );
        AbstractEncryptionElement encEl = encInfo.getEncryptedDataElements().get( 0 );

        List<Element> matchedEncKeyInEncData =
            (List<Element>) DomUtilities.findChildren( encEl.getEncryptedElement(), "EncryptedKey", URI_NS_ENC, true );
        assertEquals( 1, matchedEncKeyInEncData.size() );

        EncryptedDataElement encDataPay =
            new EncryptedDataElement( (Element) encEl.getEncryptedElement().cloneNode( true ) );
        ( (CipherValueElement) encDataPay.getCipherDataChild() ).setEncryptedData( attackContentData );
        ElementAttackProperties attackProps = encEl.getAttackProperties();
        attackProps.setWrappingPayloadElement( encDataPay.getEncryptedElement() );

        m_EncWrappOracle = new EncryptionWrappingOracle( encEl, detectReport, m_SchemaAnalyser );
        max = m_EncWrappOracle.maxPossibilities();
        AbstractDetectionFilter errorFilter = FactoryFilter.createFilter( DetectFilterEnum.AVOIDDOCFILTER );
        ( (AvoidedDocErrorFilter) errorFilter ).setPayloadInput( encEl );
        AbstractDetectionInfo errorInfo = null;

        // modified encData cipher
        assertTrue( 0 < max );
        for ( int i = 0; max > i; i++ )
        {
            possAvoidedDoc = m_EncWrappOracle.getPossibility( i );
            List<Element> matchedData =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matchedData.size() );

            // List<Element> matchedKey1 = (List<Element>) DomUtilities.findChildren(matchedData.get(0), "EncryptedKey",
            // URI_NS_ENC, true);
            // assertEquals(1, matchedKey1.size());

            // List<Element> matchedKey2 = (List<Element>) DomUtilities.findChildren(matchedData.get(1), "EncryptedKey",
            // URI_NS_ENC, true);
            // assertEquals(1, matchedKey2.size());

            String attackDocString = domToString( possAvoidedDoc );
            // System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!ORIGINAL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1");
            // System.out.println(attackDocString);
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encEl.getCipherDataChild().getEncryptedData() ) );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( attackContentData ) );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encEl.getKeyInfoElement().getEncryptedKeyElement().getCipherDataChild().getEncryptedData() ) );

        }

        // modified encKey cipher
        EncryptedDataElement encDataPay2 =
            new EncryptedDataElement( (Element) encEl.getEncryptedElement().cloneNode( true ) );
        encDataPay2.getKeyInfoElement().getEncryptedKeyElement().getCipherDataChild().setEncryptedData( attackContentKey );
        ElementAttackProperties attackProps2 = encEl.getAttackProperties();
        attackProps2.setWrappingPayloadElement( encDataPay2.getEncryptedElement() );
        ( (AvoidedDocErrorFilter) errorFilter ).setPayloadInput( encEl );
        m_EncWrappOracle = new EncryptionWrappingOracle( encEl, detectReport, m_SchemaAnalyser );
        max = m_EncWrappOracle.maxPossibilities();
        assertTrue( 0 < max );
        for ( int i = 0; max > i; i++ )
        {
            possAvoidedDoc = m_EncWrappOracle.getPossibility( i );
            List<Element> matchedData =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matchedData.size() );

            // List<Element> matchedKey1 = (List<Element>) DomUtilities.findChildren(matchedData.get(0), "EncryptedKey",
            // URI_NS_ENC, true);
            // assertEquals(1, matchedKey1.size());

            // List<Element> matchedKey2 = (List<Element>) DomUtilities.findChildren(matchedData.get(1), "EncryptedKey",
            // URI_NS_ENC, true);
            // assertEquals(1, matchedKey2.size());

            String attackDocString = domToString( possAvoidedDoc );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encEl.getCipherDataChild().getEncryptedData() ) );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encEl.getKeyInfoElement().getEncryptedKeyElement().getCipherDataChild().getEncryptedData() ) );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( attackContentKey ) );
            assertFalse( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                         attackDocString.contains( attackContentData ) );

            ( (AvoidedDocErrorFilter) errorFilter ).setInputDocument( possAvoidedDoc );
            errorInfo = ( (AvoidedDocErrorFilter) errorFilter ).process();

        }

    }

    /*
     * @Test public void testWrappingWithoutSignedEncElement() throws Exception { }
     * @Test public void testWrappingDirectlySignedEncElement() throws Exception { }
     * @Test public void testWrappingWithoutNameSpacePrefixElement() throws Exception { }
     */

    @Test
    public void testEncKeyEncDataSignedWrappingAddEncTypeWeakness()
        throws Exception
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/schema_encKey_encData_sig.xml" );
        Document possAvoidedDoc = null;
        int max = 0;
        String attackContent = "ENCRYPTED ATTACK PAYLOAD";
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );
        EncryptedKeyElement encKey = encInfo.getEncryptedKeyElements().get( 0 );
        AbstractEncryptionElement encEl =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();
        EncryptedDataElement encDataPay =
            new EncryptedDataElement( (Element) encEl.getEncryptedElement().cloneNode( true ) );
        ( (CipherValueElement) encDataPay.getCipherDataChild() ).setEncryptedData( attackContent );
        ElementAttackProperties attackProps = encEl.getAttackProperties();
        attackProps.setWrappingPayloadElement( encDataPay.getEncryptedElement() );

        assertFalse( encDataPay.getCipherDataChild().getEncryptedData().equals( encEl.getCipherDataChild().getEncryptedData() ) );

        m_EncWrappOracle = new EncryptionWrappingOracle( encKey, detectReport, m_SchemaAnalyser );
        max = m_EncWrappOracle.maxPossibilities();
        assertTrue( 0 < max );

        for ( int i = 0; max > i; i++ )
        {
            possAvoidedDoc = m_EncWrappOracle.getPossibility( i );
            List<Element> matchedData =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matchedData.size() );
            List<Element> matchedKey =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedKey", URI_NS_ENC, true );
            assertEquals( 1, matchedKey.size() );
            String attackDocString = domToString( possAvoidedDoc );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encEl.getCipherDataChild().getEncryptedData() ) );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ), attackDocString.contains( attackContent ) );
            // System.out.println(attackDocString);
            // references?
        }

        m_EncWrappOracle.addAdditionalEncryptionWeakness( FactoryWeakness.generateWeakness( WeaknessType.ATTR_TYPE_WEAKNESS,
                                                                                            encDataPay, null ) );
        int maxAddWeak = m_EncWrappOracle.maxPossibilities();
        assertTrue( 0 < maxAddWeak );
        assertTrue( 2 * max == maxAddWeak );
        int sameType = 0;
        int differentType = 0;
        for ( int i = 0; maxAddWeak > i; i++ )
        {
            possAvoidedDoc = m_EncWrappOracle.getPossibility( i );
            List<Element> matchedData =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matchedData.size() );
            List<Element> matchedKey =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedKey", URI_NS_ENC, true );
            assertEquals( 1, matchedKey.size() );

            if ( matchedData.get( 0 ).getAttributeNode( "Type" ).getValue().equals( matchedData.get( 1 ).getAttributeNode( "Type" ).getValue() ) )
            {
                sameType++;
            }
            else
            {
                differentType++;
            }

            String attackDocString = domToString( possAvoidedDoc );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encEl.getCipherDataChild().getEncryptedData() ) );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ), attackDocString.contains( attackContent ) );
            // System.out.println(attackDocString);
            // references?
        }
        assertTrue( sameType == max );
        assertTrue( differentType == max );

    }
}
