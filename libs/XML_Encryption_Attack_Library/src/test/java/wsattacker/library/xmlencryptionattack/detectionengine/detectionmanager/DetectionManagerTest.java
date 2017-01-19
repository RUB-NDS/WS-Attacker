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
package wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import javax.xml.xpath.XPathExpressionException;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.CipherValueElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.KeyInfoElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 */
public class DetectionManagerTest
{

    private SignatureManager m_SigManager;

    private Pipeline m_PipeLine;

    public DetectionManagerTest()
    {
        m_PipeLine = new Pipeline();
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.ENCRYPTIONFILTER ) );
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.SIGNATUREFILTER ) );
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
    public void testDetectEncKeyEncDataSigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_encData_signed.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );

        // encKEy properties
        assertEquals( 1, encInfo.getEncryptedKeyElements().size() );
        EncryptedKeyElement encKey = encInfo.getEncryptedKeyElements().get( 0 );
        assertEquals( "EncryptedKey", encKey.getEncryptedElement().getLocalName() );
        assertEquals( "Y1G4IvsVfHLHWEW89D7wC7wVYfks1/Q5JHru0NaZlDE89rRTIITZrjjS6ajcXcjNiRcQM"
                          + "bElYoG4tnfXOyqOYYPAWaBGXbQIQo+jFZq+hHfYt+j8YrOP8hg9uELzwtmPT7GAv1bFn+"
                          + "dEwEU6Ez5ZdCVH0cImWcf1fdezMkxvXcY=",
                      ( (CipherValueElement) encKey.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#rsa-1_5", encKey.getEncryptionMethod() );
        assertEquals( "EncKeyId-urn:uuid:64DB4A7E53F67EF3F112142272504712", encKey.getIdValue() );
        ElementAttackProperties attackPropsKey = encKey.getAttackProperties();
        assertNull( attackPropsKey.getSignedPart() );
        assertEquals( 1, encKey.getReferenceElementList().size() );
        assertEquals( -1, attackPropsKey.getSignMode() );

        // encData properties
        AbstractEncryptionElement encEl =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();
        ElementAttackProperties attackPropsData = encEl.getAttackProperties();
        Element signedElement = attackPropsData.getSignedPart();
        assertEquals( "Body", signedElement.getLocalName() );
        assertEquals( "EncryptedData", encEl.getEncryptedElement().getLocalName() );
        assertEquals( "lSDNH2zpu/R0039i85GoB93Sp2hg3rl20exTPccmN26YCt9rX54cbXFDwbZuIATYl52YPYHk"
                          + "HLK1WZP0JW+o7G8mjPAxiwBUK5hWwoOO1/I35wV7wJIvARS6CxS+IhHK3fnXsee8nLZulYaH1LD"
                          + "v7R+if2S1/v6YdhNodtZh2UqEZq0iHkr+GChEDwWpaiOUnyQ8mJS3hRq4GYnJEk4apQBIeuF8t64mN"
                          + "mY+ISlqNvQes2w5YVOsTUptmH4HPyVnfRuO/5tr7VNbh00myh0/309W8qgLCUlMJqN9nRa1v5+MX9t"
                          + "68pUgg92V1bV/46wE4xGDxyGgxk9asrJDvt+vNreMl5o3dOnvIaI8W5Dwpp/o7IkMtlFlT3aP7cETJ"
                          + "/Kb7VXLasQju2qPnSceXLJOWjLmMlqf9HraAmjaM/IbyEo=",
                      ( (CipherValueElement) encEl.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encEl.getEncryptionMethod() );
        assertEquals( "EncDataId-3808966", encEl.getIdValue() );
        short signMode = ( Node.DOCUMENT_POSITION_CONTAINED_BY | Node.DOCUMENT_POSITION_FOLLOWING );
        assertEquals( signMode, attackPropsData.getSignMode() );

        // encData only properties
        assertEquals( 0, encInfo.getEncryptedDataElements().size() );

        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());

    }

    @Test
    public void testDetectEncKeyInsideEncDataSigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_inside_encData_signed.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );

        // encKey properties
        assertEquals( 0, encInfo.getEncryptedKeyElements().size() );

        // EncData only
        assertEquals( 1, encInfo.getEncryptedDataElements().size() );
        EncryptedDataElement encDataOnly = encInfo.getEncryptedDataElements().get( 0 );
        ElementAttackProperties attackPropsData = encDataOnly.getAttackProperties();
        Element signedElement = attackPropsData.getSignedPart();
        assertEquals( "Body", signedElement.getLocalName() );
        assertEquals( "EncryptedData", encDataOnly.getEncryptedElement().getLocalName() );
        assertEquals( "UM2LlzEpNjpgdupv3Kd6ELb4q2HxR4ligF9WOIIbXMU=",
                      ( (CipherValueElement) encDataOnly.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#aes128-cbc", encDataOnly.getEncryptionMethod() );
        assertEquals( "ED-2", encDataOnly.getIdValue() );
        short signMode = ( Node.DOCUMENT_POSITION_CONTAINED_BY | Node.DOCUMENT_POSITION_FOLLOWING );
        assertEquals( signMode, attackPropsData.getSignMode() );
        assertNotNull( encDataOnly.getKeyInfoElement() );
        KeyInfoElement keyInfo = encDataOnly.getKeyInfoElement();
        assertEquals( "KeyInfo", keyInfo.getKeyInfoElement().getLocalName() );
        EncryptedKeyElement encKey = keyInfo.getEncryptedKeyElement();
        assertEquals( "EncryptedKey", encKey.getEncryptedElement().getLocalName() );
        assertEquals( "EncKeyId-urn:uuid:64DB4A7E53F67EF3F112142272504712", encKey.getIdValue() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#rsa-1_5", encKey.getEncryptionMethod() );

        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());

    }

    @Test
    public void testNoEncNoSigElements()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_no_signed_no_encryption.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( !sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 0, m_SigManager.getPayloads().size() );

        // encKey properties
        assertEquals( 0, encInfo.getEncryptedKeyElements().size() );

        // encData only properties
        assertEquals( 0, encInfo.getEncryptedDataElements().size() );

        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());
    }

    @Test
    public void testDetectEncKeyMultipleEncDataSigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        ElementAttackProperties attackPropsData = null;
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_multiple_encData_signed.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        assertEquals( 1, encInfo.getEncryptedKeyElements().size() );
        assertEquals( 0, encInfo.getEncryptedDataElements().size() );
        attackPropsData = encInfo.getEncryptedKeyElements().get( 0 ).getAttackProperties();
        assertNull( attackPropsData.getSignedPart() );
        assertEquals( 4, encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().size() );

        List<AbstractRefElement> keyDataRefs = encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList();
        attackPropsData = ( (DataReferenceElement) keyDataRefs.get( 0 ) ).getRefEncData().getAttackProperties();
        assertNotNull( attackPropsData.getSignedPart() );
        attackPropsData = ( (DataReferenceElement) keyDataRefs.get( 1 ) ).getRefEncData().getAttackProperties();
        assertNotNull( attackPropsData.getSignedPart() );
        attackPropsData = ( (DataReferenceElement) keyDataRefs.get( 2 ) ).getRefEncData().getAttackProperties();
        assertNotNull( attackPropsData.getSignedPart() );
        attackPropsData = ( (DataReferenceElement) keyDataRefs.get( 3 ) ).getRefEncData().getAttackProperties();
        assertNull( attackPropsData.getSignedPart() );

        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());
    }

    @Test
    public void testDetectEncKeySignedEncDataSigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_signed_encData_signed.xml" );
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

        // encKey properties
        assertEquals( 1, encInfo.getEncryptedKeyElements().size() );
        EncryptedKeyElement encKey = encInfo.getEncryptedKeyElements().get( 0 );
        assertEquals( "EncryptedKey", encKey.getEncryptedElement().getLocalName() );
        assertEquals( "Y1G4IvsVfHLHWEW89D7wC7wVYfks1/Q5JHru0NaZlDE89rRTIITZrjjS6ajcXcjNiRcQM"
                          + "bElYoG4tnfXOyqOYYPAWaBGXbQIQo+jFZq+hHfYt+j8YrOP8hg9uELzwtmPT7GAv1bFn+"
                          + "dEwEU6Ez5ZdCVH0cImWcf1fdezMkxvXcY=",
                      ( (CipherValueElement) encKey.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#rsa-1_5", encKey.getEncryptionMethod() );
        assertEquals( "EncKeyId-urn:uuid:64DB4A7E53F67EF3F112142272504712", encKey.getIdValue() );
        ElementAttackProperties attackPropsKey = encKey.getAttackProperties();
        assertNotNull( attackPropsKey.getSignedPart() );
        assertEquals( "EncryptedKey", attackPropsKey.getSignedPart().getLocalName() );
        assertEquals( 1, encKey.getReferenceElementList().size() );
        assertEquals( 0, attackPropsKey.getSignMode() );

        // encData properties
        AbstractEncryptionElement encEl =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();
        ElementAttackProperties attackPropsData = encEl.getAttackProperties();
        Element signedElement = attackPropsData.getSignedPart();
        assertEquals( "Body", signedElement.getLocalName() );
        assertEquals( "EncryptedData", encEl.getEncryptedElement().getLocalName() );
        assertEquals( "lSDNH2zpu/R0039i85GoB93Sp2hg3rl20exTPccmN26YCt9rX54cbXFDwbZuIATYl52YPYHk"
                          + "HLK1WZP0JW+o7G8mjPAxiwBUK5hWwoOO1/I35wV7wJIvARS6CxS+IhHK3fnXsee8nLZulYaH1LD"
                          + "v7R+if2S1/v6YdhNodtZh2UqEZq0iHkr+GChEDwWpaiOUnyQ8mJS3hRq4GYnJEk4apQBIeuF8t64mN"
                          + "mY+ISlqNvQes2w5YVOsTUptmH4HPyVnfRuO/5tr7VNbh00myh0/309W8qgLCUlMJqN9nRa1v5+MX9t"
                          + "68pUgg92V1bV/46wE4xGDxyGgxk9asrJDvt+vNreMl5o3dOnvIaI8W5Dwpp/o7IkMtlFlT3aP7cETJ"
                          + "/Kb7VXLasQju2qPnSceXLJOWjLmMlqf9HraAmjaM/IbyEo=",
                      ( (CipherValueElement) encEl.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encEl.getEncryptionMethod() );
        assertEquals( "EncDataId-3808966", encEl.getIdValue() );
        short signMode = ( Node.DOCUMENT_POSITION_CONTAINED_BY | Node.DOCUMENT_POSITION_FOLLOWING );
        assertEquals( signMode, attackPropsData.getSignMode() );

        // encData only properties
        assertEquals( 0, encInfo.getEncryptedDataElements().size() );
        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());

    }

    @Test
    public void testDetectEncDataOnlySigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encData_signed.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );

        // encKey properties
        assertEquals( 0, encInfo.getEncryptedKeyElements().size() );

        // encDataOnly properties
        assertEquals( 1, encInfo.getEncryptedDataElements().size() );
        EncryptedDataElement encEl = encInfo.getEncryptedDataElements().get( 0 );
        ElementAttackProperties attackPropsData = encEl.getAttackProperties();
        Element signedElement = attackPropsData.getSignedPart();
        assertEquals( "Body", signedElement.getLocalName() );
        assertEquals( "EncryptedData", encEl.getEncryptedElement().getLocalName() );
        assertEquals( "vgfFucuY8GHvtgxa2fd6ClNzCIlAtPT5DjPEirQGfkQG54PD/hMxndKXo1XiVj01bf/70in"
            + "4tjHCXSGjLzYmAdsPfUn+lowHE/zgq6KAAzxAxcfCQ6ta7qzbOI9yVzYmFRKywGZQ88VMOI"
            + "A6sDr6xw5fm0KCPAkFbIse1DqRhXWeTjGNvOFPNCdxI+4NRNZFwJzceVS7LuZFzTi0jVA3h"
            + "Z7CLfq8KwTShJwJiSG6PKnBkWr1ewiD4CDxjMCWVTonnCapSPp4MGJlMM9yB+7Tytv6zJpx"
            + "5Hru89wXg97DUB5g7xuCZ1mR97XBcvT7GXKF9ji5LNgBlWrN+CJvgTF8JNGqrUDC6vwBD51"
            + "fXI2b2hkfeqS9W605ntOPRWOWJrxm", ( (CipherValueElement) encEl.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#aes128-cbc", encEl.getEncryptionMethod() );
        assertEquals( "ED-4", encEl.getIdValue() );
        short signMode = ( Node.DOCUMENT_POSITION_CONTAINED_BY | Node.DOCUMENT_POSITION_FOLLOWING );
        assertEquals( signMode, attackPropsData.getSignMode() );
        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());
    }

    @Test
    public void testDetectEncDataOnly()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encData_only.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertFalse( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 0, m_SigManager.getPayloads().size() );

        // encKey properties
        assertEquals( 0, encInfo.getEncryptedKeyElements().size() );

        // encDataOnly properties
        assertEquals( 1, encInfo.getEncryptedDataElements().size() );
        EncryptedDataElement encEl = encInfo.getEncryptedDataElements().get( 0 );
        ElementAttackProperties attackPropsData = encEl.getAttackProperties();
        Element signedElement = attackPropsData.getSignedPart();
        assertNull( signedElement );
        assertEquals( "EncryptedData", encEl.getEncryptedElement().getLocalName() );
        assertEquals( "UM2LlzEpNjpgdupv3Kd6ELb4q2HxR4ligF9WOIIbXMU=",
                      ( (CipherValueElement) encEl.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#aes128-cbc", encEl.getEncryptionMethod() );
        assertEquals( "ED-1", encEl.getIdValue() );
        assertEquals( -1, attackPropsData.getSignMode() );
        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());
    }

    @Test
    public void testDetectSignedElementNoEnc()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_signed_no_encryption.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 2, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );
        assertEquals( "Timestamp", m_SigManager.getPayloads().get( 1 ).getSignedElement().getLocalName() );

        // encKey properties
        assertEquals( 0, encInfo.getEncryptedKeyElements().size() );

        // encDataOnly properties
        assertEquals( 0, encInfo.getEncryptedDataElements().size() );
        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());
    }

    @Test
    public void testDetectEncKeyEncData()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_encData.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertFalse( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 0, m_SigManager.getPayloads().size() );

        // encKEy properties
        assertEquals( 1, encInfo.getEncryptedKeyElements().size() );
        EncryptedKeyElement encKey = encInfo.getEncryptedKeyElements().get( 0 );
        assertEquals( "EncryptedKey", encKey.getEncryptedElement().getLocalName() );
        assertEquals( "Y1G4IvsVfHLHWEW89D7wC7wVYfks1/Q5JHru0NaZlDE89rRTIITZrjjS6ajcXcjNiRcQM"
                          + "bElYoG4tnfXOyqOYYPAWaBGXbQIQo+jFZq+hHfYt+j8YrOP8hg9uELzwtmPT7GAv1bFn+"
                          + "dEwEU6Ez5ZdCVH0cImWcf1fdezMkxvXcY=",
                      ( (CipherValueElement) encKey.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#rsa-1_5", encKey.getEncryptionMethod() );
        assertEquals( "EncKeyId-urn:uuid:64DB4A7E53F67EF3F112142272504712", encKey.getIdValue() );
        ElementAttackProperties attackPropsKey = encKey.getAttackProperties();
        assertNull( attackPropsKey.getSignedPart() );
        assertEquals( 1, encKey.getReferenceElementList().size() );
        assertEquals( -1, attackPropsKey.getSignMode() );

        // encData properties
        AbstractEncryptionElement encEl =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();
        ElementAttackProperties attackPropsData = encEl.getAttackProperties();
        Element signedElement = attackPropsData.getSignedPart();
        assertNull( signedElement );
        assertEquals( "EncryptedData", encEl.getEncryptedElement().getLocalName() );
        assertEquals( "lSDNH2zpu/R0039i85GoB93Sp2hg3rl20exTPccmN26YCt9rX54cbXFDwbZuIATYl52YPYHk"
                          + "HLK1WZP0JW+o7G8mjPAxiwBUK5hWwoOO1/I35wV7wJIvARS6CxS+IhHK3fnXsee8nLZulYaH1LD"
                          + "v7R+if2S1/v6YdhNodtZh2UqEZq0iHkr+GChEDwWpaiOUnyQ8mJS3hRq4GYnJEk4apQBIeuF8t64mN"
                          + "mY+ISlqNvQes2w5YVOsTUptmH4HPyVnfRuO/5tr7VNbh00myh0/309W8qgLCUlMJqN9nRa1v5+MX9t"
                          + "68pUgg92V1bV/46wE4xGDxyGgxk9asrJDvt+vNreMl5o3dOnvIaI8W5Dwpp/o7IkMtlFlT3aP7cETJ"
                          + "/Kb7VXLasQju2qPnSceXLJOWjLmMlqf9HraAmjaM/IbyEo=",
                      ( (CipherValueElement) encEl.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encEl.getEncryptionMethod() );
        assertEquals( "EncDataId-3808966", encEl.getIdValue() );
        assertEquals( -1, attackPropsData.getSignMode() );

        // encData only properties
        assertEquals( 0, encInfo.getEncryptedDataElements().size() );

        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());

    }

    @Test
    public void testDetectEncKeyInsideEncData()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_inside_encData.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertFalse( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 0, m_SigManager.getPayloads().size() );

        // encKey properties
        assertEquals( 0, encInfo.getEncryptedKeyElements().size() );

        // EncData only
        assertEquals( 1, encInfo.getEncryptedDataElements().size() );
        EncryptedDataElement encDataOnly = encInfo.getEncryptedDataElements().get( 0 );
        ElementAttackProperties attackPropsData = encDataOnly.getAttackProperties();
        Element signedElement = attackPropsData.getSignedPart();
        assertNull( signedElement );
        assertEquals( "EncryptedData", encDataOnly.getEncryptedElement().getLocalName() );
        assertEquals( "UM2LlzEpNjpgdupv3Kd6ELb4q2HxR4ligF9WOIIbXMU=",
                      ( (CipherValueElement) encDataOnly.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#aes128-cbc", encDataOnly.getEncryptionMethod() );
        assertEquals( "ED-2", encDataOnly.getIdValue() );
        short signMode = ( Node.DOCUMENT_POSITION_CONTAINED_BY | Node.DOCUMENT_POSITION_FOLLOWING );
        assertEquals( -1, attackPropsData.getSignMode() );
        assertNotNull( encDataOnly.getKeyInfoElement() );
        KeyInfoElement keyInfo = encDataOnly.getKeyInfoElement();
        assertEquals( "KeyInfo", keyInfo.getKeyInfoElement().getLocalName() );
        EncryptedKeyElement encKey = keyInfo.getEncryptedKeyElement();
        assertEquals( "EncryptedKey", encKey.getEncryptedElement().getLocalName() );
        assertEquals( "EncKeyId-urn:uuid:64DB4A7E53F67EF3F112142272504712", encKey.getIdValue() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#rsa-1_5", encKey.getEncryptionMethod() );

        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());

    }

    @Test
    public void testDetectEncKeyEncDataSignedNoPrefix()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encKey_encData_signed_noPrefix.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );

        // encKEy properties
        assertEquals( 1, encInfo.getEncryptedKeyElements().size() );
        EncryptedKeyElement encKey = encInfo.getEncryptedKeyElements().get( 0 );
        assertEquals( "EncryptedKey", encKey.getEncryptedElement().getLocalName() );
        assertEquals( "Y1G4IvsVfHLHWEW89D7wC7wVYfks1/Q5JHru0NaZlDE89rRTIITZrjjS6ajcXcjNiRcQM"
                          + "bElYoG4tnfXOyqOYYPAWaBGXbQIQo+jFZq+hHfYt+j8YrOP8hg9uELzwtmPT7GAv1bFn+"
                          + "dEwEU6Ez5ZdCVH0cImWcf1fdezMkxvXcY=",
                      ( (CipherValueElement) encKey.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#rsa-1_5", encKey.getEncryptionMethod() );
        assertEquals( "EncKeyId-urn:uuid:64DB4A7E53F67EF3F112142272504712", encKey.getIdValue() );
        ElementAttackProperties attackPropsKey = encKey.getAttackProperties();
        assertNull( attackPropsKey.getSignedPart() );
        assertEquals( 1, encKey.getReferenceElementList().size() );
        assertEquals( -1, attackPropsKey.getSignMode() );

        // encData properties
        AbstractEncryptionElement encEl =
            ( (DataReferenceElement) encInfo.getEncryptedKeyElements().get( 0 ).getReferenceElementList().get( 0 ) ).getRefEncData();
        ElementAttackProperties attackPropsData = encEl.getAttackProperties();
        Element signedElement = attackPropsData.getSignedPart();
        assertEquals( "Body", signedElement.getLocalName() );
        assertEquals( "EncryptedData", encEl.getEncryptedElement().getLocalName() );
        assertEquals( "lSDNH2zpu/R0039i85GoB93Sp2hg3rl20exTPccmN26YCt9rX54cbXFDwbZuIATYl52YPYHk"
                          + "HLK1WZP0JW+o7G8mjPAxiwBUK5hWwoOO1/I35wV7wJIvARS6CxS+IhHK3fnXsee8nLZulYaH1LD"
                          + "v7R+if2S1/v6YdhNodtZh2UqEZq0iHkr+GChEDwWpaiOUnyQ8mJS3hRq4GYnJEk4apQBIeuF8t64mN"
                          + "mY+ISlqNvQes2w5YVOsTUptmH4HPyVnfRuO/5tr7VNbh00myh0/309W8qgLCUlMJqN9nRa1v5+MX9t"
                          + "68pUgg92V1bV/46wE4xGDxyGgxk9asrJDvt+vNreMl5o3dOnvIaI8W5Dwpp/o7IkMtlFlT3aP7cETJ"
                          + "/Kb7VXLasQju2qPnSceXLJOWjLmMlqf9HraAmjaM/IbyEo=",
                      ( (CipherValueElement) encEl.getCipherDataChild() ).getEncryptedData() );
        assertEquals( "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encEl.getEncryptionMethod() );
        assertEquals( "EncDataId-3808966", encEl.getIdValue() );
        short signMode = ( Node.DOCUMENT_POSITION_CONTAINED_BY | Node.DOCUMENT_POSITION_FOLLOWING );
        assertEquals( signMode, attackPropsData.getSignMode() );

        // encData only properties
        assertEquals( 0, encInfo.getEncryptedDataElements().size() );

        assertEquals( doc, detectReport.getRawFile() );
        // assertNull(detectReport.getAvoidedFile());

    }
    /*
     * case_encKey_encData_signed case_no_signed_no_encryption.xml case_encKey_Inside_encData_signed.xml
     * case_encKey_multiple_encData_signed.xml case_encKey_sigend_encData_signed.xml case_encData_signed.xml
     * case_encData_only.xml case_signed_no_encryption.xml case_encKey_encData.xml
     * case_multiple_encKey_multiple_encData_signed.xml case_encKey_inside_encData.xml
     * case_encKey_encData_signed_noPrefix.xml
     */
}
