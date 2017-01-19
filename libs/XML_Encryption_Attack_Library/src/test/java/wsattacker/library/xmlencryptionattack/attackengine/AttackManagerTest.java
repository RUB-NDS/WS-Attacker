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

package wsattacker.library.xmlencryptionattack.attackengine;

import java.util.List;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.EncSigWrappingOracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.EncryptionWrappingOracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptedKeyRefWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptionAttributeIdWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptionSchemaWeakness;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectionManager;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.FactoryFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.Pipeline;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete.AvoidedDocErrorFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory.SimStringStrategy;
import static wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory.SimStringStrategy.DICE_COEFF;
import static wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory.createSimStringStrategy;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 */
public class AttackManagerTest
{
    private static SchemaAnalyzer m_SchemaAnalyser;

    private static Logger log;

    private DetectionManager m_DetectManager = null;

    private Pipeline m_PipeLine = null;

    private EncryptionWrappingOracle m_EncWrappOracle = null;

    private Document m_RawFile = null;

    private SignatureManager m_SigManager;

    public AttackManagerTest()
    {
        m_PipeLine = new Pipeline();
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.ENCRYPTIONFILTER ) );
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.SIGNATUREFILTER ) );
        Logger.getLogger( EncryptedKeyRefWeakness.class ).setLevel( Level.OFF );
        Logger.getLogger( EncryptionAttributeIdWeakness.class ).setLevel( Level.OFF );
        Logger.getLogger( EncryptionSchemaWeakness.class ).setLevel( Level.OFF );
        m_SchemaAnalyser = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );
    }

    @BeforeClass
    public static void setUpClass()
    {
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

    /**
     * Test of getDetectionReport method, of class AttackManager.
     */
    @Test
    public void testGetDetectionReport()
    {
        /*
         * System.out.println("getDetectionReport"); AttackManager instance = null; DetectionReport expResult = null;
         * DetectionReport result = instance.getDetectionReport(); assertEquals(expResult, result); // TODO review the
         * generated test code and remove the default call to fail. //fail("The test case is a prototype.");
         */
    }

    /**
     * Test of getInputFile method, of class AttackManager.
     */
    @Test
    public void testGetInputFile()
    {
        /*
         * System.out.println("getInputFile"); AttackManager instance = null; Document expResult = null; Document result
         * = instance.getInputFile(); assertEquals(expResult, result); // TODO review the generated test code and remove
         * the default call to fail. //fail("The test case is a prototype.");
         */
    }

    /**
     * Test of getAvoidedFile method, of class AttackManager.
     */
    @Test
    public void testGetAvoidedFile()
    {
        /*
         * System.out.println("getAvoidedFile"); AttackManager instance = null; Document expResult = null; Document
         * result = instance.getAvoidedFile(); assertEquals(expResult, result); // TODO review the generated test code
         * and remove the default call to fail. //fail("The test case is a prototype.");
         */
    }

    /**
     * Test of getXMLEncryptionAttack method, of class AttackManager.
     */
    @Test
    public void testGetXMLEncryptionAttack()
    {
        /*
         * System.out.println("getXMLEncryptionAttack"); AttackManager instance = null; XMLEncryptionAttack expResult =
         * null; XMLEncryptionAttack result = instance.getXMLEncryptionAttack(); assertEquals(expResult, result); //
         * TODO review the generated test code and remove the default call to fail.
         * //fail("The test case is a prototype.");
         */
    }

    /**
     * Test of executeAttack method, of class AttackManager.
     */
    @Test
    public void testExecuteAttack()
    {
        String tempScore = createSimStringStrategy( DICE_COEFF ).getShortDescriptionString();
        /*
         * AttackManager instance = null; byte[] expResult = null; byte[] result = instance.executeAttack();
         * assertArrayEquals(expResult, result); // TODO review the generated test code and remove the default call to
         * fail. //fail("The test case is a prototype.");
         */    }

    @Test
    public void testAttackOnEncKeyWithSignedEncData()
        throws Exception
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/schema_encKey_encData_sig.xml" );
        Document possAvoidedDoc = null;
        EncSigWrappingOracle encSigWrappOracle = null;
        EncryptionWrappingOracle encWrappOracle = null;
        AbstractDetectionInfo errorInfo = null;
        AbstractDetectionFilter errorFilter = null;
        AttackConfig attackCfg = new AttackConfig();
        AOracle oracle = null;

        // start to analyse input file
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
        // set error filter for wrapping position detection
        errorFilter = FactoryFilter.createFilter( DetectFilterEnum.AVOIDDOCFILTER );
        ( (AvoidedDocErrorFilter) errorFilter ).setPayloadInput( encEl );

        setPayload( detectReport, encEl );
        configureAttack( attackCfg );

        // start to avoid possible countermeasures
        encSigWrappOracle = new EncSigWrappingOracle( encKey, detectReport, m_SchemaAnalyser );
        encWrappOracle = new EncryptionWrappingOracle( encKey, detectReport, m_SchemaAnalyser );

        // encSig wrapping attack
        if ( attackCfg.getWrappingMode() == WrappingAttackMode.SIGNATURE )
        {
            errorInfo = startEncSigWrapping( encSigWrappOracle, errorFilter );
        }

        // encryption wrapping attack
        if ( attackCfg.getWrappingMode() == WrappingAttackMode.ENCRYPTION )
        {
            errorInfo = startEncryptionWrapping( encWrappOracle, errorFilter );
        }

        // !!! important !! save payload element (wrapped element in wrapping attack doucument (avoidedFile))
        // important information for encryption attack:
        // 1. which is the payload element => for modifying ciphervalue
        // 2. the valid wrapping document (result of wrapping attacks)
        // => information saved in errorInfo-object of WAVOIDDOCFILTER
        // detectReport.addDetectionInfo(DetectFilterEnum.WRAVOIDDOCFILTERerrorInfo);

        // generate requests and serverresponse in tab (TODO) !!!!!!
        // CBCVectorGenerator.generateVectors(cipherBlockSize);
        // PKCS1VectorGenerator.generatePkcs1Vectors(null, CryptoConstants.Algorithm.CBC_AES128, true)
        // get public key??
        // getServerBehaviour()

        // save error table in detectionReport
        detectReport.setErrorResponseTab( null );

        // init oracle with:
        // 1.) detectionReport for getting info objects
        // 2.) string similarity strategy for comparing attack requests (user can choose...have to analyse which is the
        // optimal one
        // oracle = new CBCErrorOracle(detectReport,attackCfg.getSimStringStrategyType());

        // init attackmanager who executes the configured attack parameters
        // attackManager = new AttackManager(detectReport, attackCfg, oracle);
        // attackManager.executeAttack();

    }

    private void configureAttack( AttackConfig attackCfg )
    {
        attackCfg.setWrappingMode( WrappingAttackMode.ENCRYPTION );
        attackCfg.setOracleMode( XMLEncryptionConstants.OracleMode.ERROR_ORACLE );
        attackCfg.setXMLEncryptionAttack( XMLEncryptionConstants.XMLEncryptionAttackMode.CBC_ATTACK );
        attackCfg.setSimStringStrategyType( SimStringStrategy.LEVENSTHEIN );
    }

    private void setPayload( DetectionReport detectReport, AbstractEncryptionElement encEl )
        throws IllegalArgumentException
    {
        List<Payload> pays =
            ( (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER ) ).getSignatureManager().getPayloads();
        for ( int i = 0; pays.size() > i; i++ )
        {
            pays.get( i ).setValue( pays.get( i ).getValue() );
            // wrappingElement in original document -> "copy" in wrapping attackdoc
            // attackDocu for wrapping attacks -> new "copy" wrapping element -> attack element for encryption attack
            // in encryption attack -> wrappingDoc => "avoided file" -> copy of avoided file + ciphervalue of chosen
            // encryption attack
            // copy of "avoided file" is the last document for encryption attack
            ElementAttackProperties attackProps = encEl.getAttackProperties();
            attackProps.setWrappingPayloadElement( encEl.getEncryptedElement() );
        }
    }

    private AbstractDetectionInfo startEncSigWrapping( EncSigWrappingOracle encSigWrappOracle,
                                                       AbstractDetectionFilter errorFilter )
        throws InvalidWeaknessException
    {
        int max;
        Document possAvoidedDoc;
        AbstractDetectionInfo errorInfo = null;
        max = encSigWrappOracle.maxPossibilities();
        for ( int i = 0; max > i; i++ )
        {
            possAvoidedDoc = encSigWrappOracle.getPossibility( i );
            // responseOriginal = send "original attack o server
            ( (AvoidedDocErrorFilter) errorFilter ).setInputDocument( possAvoidedDoc );
            errorInfo = ( (AvoidedDocErrorFilter) errorFilter ).process();

            ( (AvoidedDocErrorInfo) errorInfo ).getErrorDocument();
            // responseError = send error doc to server;
            // Compare responseOriginal with responseError
            // not equal -> wrapping pos found
            // sAvoidedDocErrorInfoInfo-Object in DetectionReport
            // abort wrapping
            break;
            // System.out.println(domToString(possAvoidedDoc));
        }
        return errorInfo;
    }

    private AbstractDetectionInfo startEncryptionWrapping( EncryptionWrappingOracle encWrappOracle,
                                                           AbstractDetectionFilter errorFilter )
        throws InvalidWeaknessException
    {
        int max;
        Document possAvoidedDoc;
        AbstractDetectionInfo errorInfo = null;
        max = encWrappOracle.maxPossibilities();
        for ( int i = 85; max > i; i++ )
        {
            possAvoidedDoc = encWrappOracle.getPossibility( i );

            ( (AvoidedDocErrorFilter) errorFilter ).setInputDocument( possAvoidedDoc );
            errorInfo = ( (AvoidedDocErrorFilter) errorFilter ).process();

            ( (AvoidedDocErrorInfo) errorInfo ).getErrorDocument();
            // responseError = send error doc to server;
            // Compare responseOriginal with responseError
            // not equal -> wrapping pos found
            // AvoidedDocErrorInfo-Object in DetectionReport
            // abort wrapping
            break;
            // System.out.println(domToString(possAvoidedDoc));
        }
        return errorInfo;
    }

}
