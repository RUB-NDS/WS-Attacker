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
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptedKeyRefWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptionAttributeIdWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptionSchemaWeakness;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectionManager;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.FactoryFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.Pipeline;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;

public class EncSigWrappingOracleTest
{

    private static SchemaAnalyzer m_SchemaAnalyser;

    private static Logger log;

    private DetectionManager m_DetectManager = null;

    private Pipeline m_PipeLine = null;

    private EncSigWrappingOracle m_EncSigWrappOracle = null;

    private Document m_RawFile = null;

    private SignatureManager m_SigManager;

    public EncSigWrappingOracleTest()
    {
        m_PipeLine = new Pipeline();
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.ENCRYPTIONFILTER ) );
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.SIGNATUREFILTER ) );
        Logger.getLogger( EncryptedKeyRefWeakness.class ).setLevel( Level.OFF );
        Logger.getLogger( EncryptionAttributeIdWeakness.class ).setLevel( Level.OFF );
        Logger.getLogger( EncryptionSchemaWeakness.class ).setLevel( Level.OFF );
        // Load Schema Files
        m_SchemaAnalyser = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );
    }

    @AfterClass
    public static void tearDownAfterClass()
        throws Exception
    {

    }

    @Before
    public void setUp()
        throws Exception
    {
        // log.setLevel(Level.OFF);
    }

    @After
    public void tearDown()
        throws Exception
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

        List<Payload> pays =
            ( (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER ) ).getSignatureManager().getPayloads();

        EncryptedDataElement encDataPay = null;
        List<Element> matchedEncData = null;

        ElementAttackProperties attackProps = encEl.getAttackProperties();
        pays.get( 0 ).setValue( DomUtilities.domToString( (Element) attackProps.getSignedPart() ) );
        matchedEncData =
            (List<Element>) DomUtilities.findChildren( pays.get( 0 ).getPayloadElement(), "EncryptedData", URI_NS_ENC,
                                                       true );
        assertEquals( 1, matchedEncData.size() );
        encDataPay = new EncryptedDataElement( (Element) matchedEncData.get( 0 ) );
        // encDataPay.getCipherDataChild().setEncryptedData(attackContent);
        attackProps.setWrappingPayloadElement( encEl.getEncryptedElement() );
        // assertFalse(encDataPay.getCipherDataChild().getEncryptedData().equals(encEl.getCipherDataChild().getEncryptedData()));

        m_EncSigWrappOracle = new EncSigWrappingOracle( encKey, detectReport, m_SchemaAnalyser );

        max = m_EncSigWrappOracle.maxPossibilities();
        assertTrue( 0 < max );
        for ( int i = 0; max > i; i++ )
        {
            possAvoidedDoc = m_EncSigWrappOracle.getPossibility( i );
            List<Element> matchedData =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matchedData.size() );
            List<Element> matchedKey =
                (List<Element>) DomUtilities.findChildren( possAvoidedDoc, "EncryptedKey", URI_NS_ENC, true );
            assertEquals( 1, matchedKey.size() );
            String attackDocString = domToString( possAvoidedDoc );
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encEl.getCipherDataChild().getEncryptedData() ) );
            // assertTrue("Invalid Message:\n" + domToString(possAvoidedDoc), attackDocString.contains(attackContent));
            assertTrue( "Invalid Message:\n" + domToString( possAvoidedDoc ),
                        attackDocString.contains( encKey.getCipherDataChild().getEncryptedData() ) );
            // System.out.println(attackDocString);
            // references?
        }

    }

    @Test
    public void testEncKeyElementInSignedEncDataWrapping()
        throws Exception
    {
        /*
         * Document doc = DomUtilities.readDocument("src/test/resources/case_encKey_inside_encData_signed.xml");
         * Document possAvoidedDoc = null; int max = 0; List<QName> filterList = new ArrayList<QName>(); String
         * attackContentKey = "ENCRYPTED ATTACK PAYLOAD KEY"; String attackContentData =
         * "ENCRYPTED ATTACK PAYLOAD DATA"; DetectionManager detectManager = new DetectionManager(m_PipeLine,doc);
         * detectManager.startDetection(); DetectionReport detectReport = detectManager.getDetectionReport();
         * EncryptionInfo encInfo = (EncryptionInfo)detectReport. getDetectionInfo(DetectFilterEnum.ENCRYPTIONFILTER);
         * SignatureInfo sigInfo = (SignatureInfo)detectReport. getDetectionInfo(DetectFilterEnum.SIGNATUREFILTER);
         * assertTrue(sigInfo.isSignature()); m_SigManager = sigInfo.getSignatureManager();
         * assertEquals(1,m_SigManager.getPayloads().size());
         * assertEquals("Body",m_SigManager.getPayloads().get(0).getSignedElement().getLocalName());
         * AbstractEncryptionElement encEl = encInfo.getEncryptedDataElements().get(0); List<Element>
         * matchedEncKeyInEncData = (List<Element>) DomUtilities. findChildren(encEl.getEncryptedElement(),
         * "EncryptedKey", URI_NS_ENC, true); assertEquals(1,matchedEncKeyInEncData.size()); List<Payload> pays =
         * ((SignatureInfo)detectReport.
         * getDetectionInfo(DetectFilterEnum.SIGNATUREFILTER)).getSignatureManager().getPayloads(); EncryptedDataElement
         * encDataPay = null; List<Element> matchedEncData = null;
         * pays.get(0).setValue(DomUtilities.domToString((Element)encEl. getAttackProperties().getSignedPart()));
         * matchedEncData = (List<Element>) DomUtilities.findChildren(pays.get(0). getPayloadElement(), "EncryptedData",
         * URI_NS_ENC, true); assertEquals(1, matchedEncData.size()); encDataPay = new
         * EncryptedDataElement((Element)matchedEncData.get(0));
         * encDataPay.getCipherDataChild().setEncryptedData(attackContentData);
         * encEl.getAttackProperties().setWrappingPayloadElement(encDataPay.getEncryptedElement());
         * sigInfo.setUsedPayloads(pays);
         * /******************************************************************************************************
         */
        /*
         * if(!sigInfo.getUsedPayloads().isEmpty()) { for (Payload payload : sigInfo.getUsedPayloads()) { Element
         * signedElement = payload.getSignedElement(); filterList.add(new QName(signedElement.getNamespaceURI(),
         * signedElement.getLocalName())); } }
         */
        /*******************************************************************************************************/

        /*
         * filterList.add(new QName(URI_NS_DS, "SignedInfo")); filterList.add(new QName(URI_NS_DS, "SignatureValue"));
         * filterList.add(new QName(URI_NS_ENC, "EncryptedData")); filterList.add(new QName(URI_NS_ENC,
         * "EncryptedKey")); m_SchemaAnalyser.setFilterList(filterList); m_EncSigWrappOracle = new
         * EncSigWrappingOracle(encEl,detectReport,m_SchemaAnalyser); max = m_EncSigWrappOracle.maxPossibilities();
         * //modified encData cipher assertTrue(0<max); for(int i = 0;max>i;i++) { possAvoidedDoc =
         * m_EncSigWrappOracle.getPossibility(i); List<Element> matchedData = (List<Element>) DomUtilities.
         * findChildren(possAvoidedDoc, "EncryptedData", URI_NS_ENC, true); assertEquals(2, matchedData.size()); String
         * attackDocString = domToString(possAvoidedDoc); assertTrue("Invalid Message:\n" + domToString(possAvoidedDoc),
         * attackDocString.contains(encEl.getCipherDataChild().getEncryptedData())); assertTrue("Invalid Message:\n" +
         * domToString(possAvoidedDoc), attackDocString.contains(attackContentData)); assertTrue("Invalid Message:\n" +
         * domToString(possAvoidedDoc), attackDocString.contains(encEl.getKeyInfoElement().
         * getEncryptedKeyElement().getCipherDataChild().getEncryptedData())); } //modified encKey cipher
         * pays.get(0).setValue(DomUtilities.domToString((Element)encEl. getAttackProperties().getSignedPart()));
         * matchedEncData = (List<Element>) DomUtilities.findChildren(pays.get(0).getPayloadElement(), "EncryptedData",
         * URI_NS_ENC, true); assertEquals(1, matchedEncData.size()); encDataPay = new
         * EncryptedDataElement((Element)matchedEncData.get(0));
         * encDataPay.getKeyInfoElement().getEncryptedKeyElement().
         * getCipherDataChild().setEncryptedData(attackContentKey);
         * encEl.getAttackProperties().setWrappingPayloadElement(encDataPay.getEncryptedElement()); m_EncSigWrappOracle
         * = new EncSigWrappingOracle(encEl,detectReport,m_SchemaAnalyser); max =
         * m_EncSigWrappOracle.maxPossibilities(); assertTrue(0<max); for(int i = 0;max>i;i++) { possAvoidedDoc =
         * m_EncSigWrappOracle.getPossibility(i); List<Element> matchedData = (List<Element>)
         * DomUtilities.findChildren(possAvoidedDoc, "EncryptedData", URI_NS_ENC, true); assertEquals(2,
         * matchedData.size()); String attackDocString = domToString(possAvoidedDoc); assertTrue("Invalid Message:\n" +
         * domToString(possAvoidedDoc), attackDocString.contains(encEl.getCipherDataChild().getEncryptedData()));
         * assertTrue("Invalid Message:\n" + domToString(possAvoidedDoc),
         * attackDocString.contains(encEl.getKeyInfoElement().getEncryptedKeyElement().
         * getCipherDataChild().getEncryptedData())); assertTrue("Invalid Message:\n" + domToString(possAvoidedDoc),
         * attackDocString.contains(attackContentKey)); assertFalse("Invalid Message:\n" + domToString(possAvoidedDoc),
         * attackDocString.contains(attackContentData)); }
         */
    }

    @Test
    public void testSignedEncElementWrapping()
        throws Exception
    {

    }

    @Test
    public void testSignedEncKeyWithSignedEncDataWrapping()
        throws Exception
    {

    }

    @Test
    public void testSignedEncKeyWithEncDataWrapping()
        throws Exception
    {

    }

    @Test
    public void testEncKeyWithSignedEncDataWrapping()
        throws Exception
    {

    }

    @Test
    public void testWrappingWithoutSignedEncElement()
        throws Exception
    {

    }

    @Test
    public void testWrappingDirectlySignedEncElement()
        throws Exception
    {

    }

    @Test
    public void testWrappingWithoutNameSpacePrefixElement()
        throws Exception
    {

    }

}
