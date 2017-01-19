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

package wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.WrapModeEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectionManager;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.FactoryFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.Pipeline;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;

/**
 * @author Dennis
 */
public class EncryptedKeyRefWeaknessTest
{

    private SignatureManager m_SigManager;

    private Pipeline m_PipeLine;

    private SchemaAnalyzer m_SchemaAnalyzer;

    private static Logger log = Logger.getLogger( EncryptionAttributeIdWeaknessTest.class );

    public EncryptedKeyRefWeaknessTest()
    {
        m_PipeLine = new Pipeline();
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.ENCRYPTIONFILTER ) );
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.SIGNATUREFILTER ) );
        m_SchemaAnalyzer = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );
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

    @Test
    public void testEncKeyEncDataSigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException,
        InvalidWeaknessException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/schema_encKey_encData_sig.xml" );
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

        EncryptedKeyRefWeakness encKeyRefWeak =
            (EncryptedKeyRefWeakness) FactoryWeakness.generateWeakness( WeaknessType.ENCKEY_REF_WEAKNESS, encEl, encKey );
        assertEquals( WrapModeEnum.ENCKEY_WRAP_ENCDATA, encKeyRefWeak.getWrapMode() );

        assertEquals( 3, encKeyRefWeak.getPossibleNumWeaks() ); // delete append,
                                                                // append only,
                                                                // delete all
        int newKeyRefCounts = 0;
        int newKeyRefURI = 0;

        // abuse the weakness
        for ( int i = 0; i < encKeyRefWeak.getPossibleNumWeaks(); ++i )
        {
            Document copyDoc = DomUtilities.createNewDomFromNode( doc.getDocumentElement() );
            Element copyEncKey = DomUtilities.findCorrespondingElement( copyDoc, encKey.getEncryptedElement() );
            Element copyPayload = (Element) copyDoc.importNode( encEl.getEncryptedElement().cloneNode( true ), true );

            copyPayload.setAttribute( "Id", "ATTACK" );
            encKeyRefWeak.abuseWeakness( i, copyEncKey, copyPayload );
            log.trace( "### " + i + ")\n" + domToString( copyDoc, true ) + "\n" );

            assertNotNull( copyEncKey );
            assertNotNull( copyPayload );

            List<Element> encKeyRefs =
                DomUtilities.findChildren( encKey.getEncryptedElement(), "DataReference", URI_NS_ENC, true );
            List<Element> encKeyPay = DomUtilities.findChildren( copyDoc, "DataReference", URI_NS_ENC, true );

            assertTrue( copyPayload.getAttribute( "Id" ).equals( "ATTACK" ) );

            if ( encKeyRefs.size() == encKeyPay.size() )
            {
                if ( !encKeyRefs.get( 0 ).getAttribute( "URI" ).equals( encKeyPay.get( 0 ).getAttribute( "URI" ) ) )
                    newKeyRefURI++;

                assertEquals( 1, encKeyPay.size() );
                assertEquals( "#ATTACK", encKeyPay.get( 0 ).getAttribute( "URI" ) );

            }
            else if ( encKeyRefs.size() != encKeyPay.size() && !encKeyPay.isEmpty() )
            {
                assertEquals( 2, encKeyPay.size() );
                assertEquals( 1, encKeyRefs.size() );
                assertTrue( encKeyPay.get( 1 ).getAttribute( "URI" ).equals( "#ATTACK" ) );
                assertTrue( encKeyPay.get( 0 ).getAttribute( "URI" ).equals( "#"
                                                                                 + encEl.getEncryptedElement().getAttribute( "Id" ) ) );
                newKeyRefCounts++;
                newKeyRefURI++;
            }
            else
            {
                assertEquals( 0, encKeyPay.size() );
                assertEquals( 1, encKeyRefs.size() );
                assertTrue( encKeyRefs.get( 0 ).getAttribute( "URI" ).equals( "#"
                                                                                  + encEl.getEncryptedElement().getAttribute( "Id" ) ) );
                newKeyRefCounts++;
                newKeyRefURI++;
            }
        }
        assertEquals( 2, newKeyRefCounts );
        assertEquals( 3, newKeyRefURI );
    }

    @Test
    public void testEncKeySignedEncData()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException,
        InvalidWeaknessException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_signed_encData.xml" );
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
        EncryptedDataElement encData =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();

        EncryptedKeyRefWeakness encKeyRefWeak =
            (EncryptedKeyRefWeakness) FactoryWeakness.generateWeakness( WeaknessType.ENCKEY_REF_WEAKNESS, encKey,
                                                                        encKey );
        assertEquals( WrapModeEnum.WRAP_ENCKEY_ENCDATA, encKeyRefWeak.getWrapMode() );

        assertEquals( 2, encKeyRefWeak.getPossibleNumWeaks() ); // delete all,
                                                                // keep refs
        int newKeyRefCounts = 0;
        int newKeyRefURI = 0;

        // abuse the weakness
        for ( int i = 0; i < encKeyRefWeak.getPossibleNumWeaks(); ++i )
        {
            Document copyDoc = DomUtilities.createNewDomFromNode( doc.getDocumentElement() );
            Element copyEncData = DomUtilities.findCorrespondingElement( copyDoc, encKey.getEncryptedElement() );
            Element copyPayload = (Element) copyDoc.importNode( encKey.getEncryptedElement().cloneNode( true ), true ); // payLoad
                                                                                                                        // encKey

            encKeyRefWeak.abuseWeakness( i, copyPayload, copyEncData );
            log.trace( "### " + i + ")\n" + domToString( copyDoc, true ) + "\n" );

            assertNotNull( copyEncData );
            assertNotNull( copyPayload );

            List<Element> encKeyRefs =
                DomUtilities.findChildren( encKey.getEncryptedElement(), "DataReference", URI_NS_ENC, true );
            List<Element> encKeyPay = DomUtilities.findChildren( copyPayload, "DataReference", URI_NS_ENC, true );

            if ( encKeyRefs.size() == encKeyPay.size() )
            {
                assertEquals( 1, encKeyRefs.size() );
                assertEquals( 1, encKeyPay.size() );
                assertTrue( encKeyRefs.get( 0 ).getAttribute( "URI" ).equals( encKeyPay.get( 0 ).getAttribute( "URI" ) ) );
            }
            else
            {
                assertEquals( 1, encKeyRefs.size() );
                assertEquals( 0, encKeyPay.size() );
                newKeyRefCounts++;
                newKeyRefURI++;
            }
        }
        assertEquals( 1, newKeyRefCounts );
        assertEquals( 1, newKeyRefURI );
    }

    @Test
    // TODO:
    public void testEncKeySignedEncDataSigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException,
        InvalidWeaknessException
    {
        /*
         * Document doc = DomUtilities.readDocument( "src/test/resources/schema_encKey_sig_encData_sig.xml");
         * DetectionManager detectManager = new DetectionManager(m_PipeLine,doc); detectManager.startDetection();
         * DetectionReport detectReport = detectManager.getDetectionReport(); EncryptionInfo encInfo =
         * (EncryptionInfo)detectReport.getDetectionInfo (DetectFilterEnum.ENCRYPTIONFILTER); SignatureInfo sigInfo =
         * (SignatureInfo )detectReport.getDetectionInfo(DetectFilterEnum.SIGNATUREFILTER);
         * assertTrue(sigInfo.isSignature()); m_SigManager = sigInfo.getSignatureManager();
         * assertEquals(2,m_SigManager.getPayloads().size()); assertEquals("EncryptedKey"
         * ,m_SigManager.getPayloads().get(0).getSignedElement ().getLocalName()); EncryptedKeyElement encKey =
         * encInfo.getEncryptedKeyElements().get(0); EncryptedDataElement encData =
         * ((DataReferenceElement)((List<AbstractRefElement>) encInfo.getEncryptedKeyElements
         * ().get(0).getReferenceElementList()).get(0)) .getRefEncData(); EncryptedKeyRefWeakness encKeyRefWeak =
         * (EncryptedKeyRefWeakness) FactoryWeakness.generateWeakness(WeaknessType.ENCKEY_REF_WEAKNESS, encKey,encKey);
         * assertEquals(EncSignedModeEnum.SIGN_ENCKEY_ENCDATA, encKeyRefWeak.getEncSignedMode());
         * assertEquals(2,encKeyRefWeak.getPossibleNumWeaks()); // delete all, keep refs int newKeyRefCounts = 0; int
         * newKeyRefURI = 0; // abuse the weakness for (int i = 0; i < encKeyRefWeak.getPossibleNumWeaks(); ++i) {
         * Document copyDoc = DomUtilities.createNewDomFromNode(doc.getDocumentElement()); Element copyEncData =
         * DomUtilities.findCorrespondingElement(copyDoc, encKey.getEncryptedElement()); Element copyPayload = (Element)
         * copyDoc.importNode(encKey.getEncryptedElement().cloneNode(true), true); // payLoad encKey
         * encKeyRefWeak.abuseWeakness(i, copyPayload , copyEncData); log.trace("### " + i + ")\n" +
         * domToString(copyDoc, true) + "\n"); assertNotNull(copyEncData); assertNotNull(copyPayload); List<Element>
         * encKeyRefs = (List<Element>) DomUtilities.findChildren(encKey.getEncryptedElement(), "DataReference",
         * URI_NS_ENC, true); List<Element> encKeyPay = (List<Element>) DomUtilities.findChildren(copyPayload,
         * "DataReference", URI_NS_ENC, true); if(encKeyRefs.size() == encKeyPay.size()) {
         * assertEquals(1,encKeyRefs.size()); assertEquals(1,encKeyPay.size()); assertTrue
         * (encKeyRefs.get(0).getAttribute("URI").equals(encKeyPay.get( 0).getAttribute("URI"))); } if(encKeyRefs.size()
         * != encKeyPay.size()) { assertEquals(1,encKeyRefs.size()); assertEquals(0,encKeyPay.size());
         * newKeyRefCounts++; newKeyRefURI++; } } assertEquals(1,newKeyRefCounts); assertEquals(1,newKeyRefURI);
         */
    }
}
