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
import java.util.ArrayList;
import java.util.List;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
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
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;
import static wsattacker.library.xmlutilities.namespace.NamespaceConstants.URI_NS_DS;

/**
 * @author Dennis
 */
public class EncryptionSchemaWeaknessTest
{
    private SignatureManager m_SigManager;

    private Pipeline m_PipeLine;

    private SchemaAnalyzer m_SchemaAnalyzer;

    private static Logger log = Logger.getLogger( EncryptionSchemaWeaknessTest.class );

    public EncryptionSchemaWeaknessTest()
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
    public void testDetectEncKeyEncDataSigned()
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

        EncryptionSchemaWeakness encSchemWeak =
            (EncryptionSchemaWeakness) FactoryWeakness.generateWeakness( WeaknessType.SCHEMA_WEAKNESS, encEl, encKey );
        assertEquals( WrapModeEnum.ENCKEY_WRAP_ENCDATA, encSchemWeak.getWrapMode() );
        List<QName> filterList = new ArrayList<QName>();
        filterList.add( new QName( URI_NS_ENC, "EncryptedData" ) );
        filterList.add( new QName( URI_NS_DS, "SignedInfo" ) );
        filterList.add( new QName( URI_NS_DS, "SignatureValue" ) );
        // wrappingpositions in signed body do not use
        filterList.add( new QName( m_SigManager.getPayloads().get( 0 ).getSignedElement().getNamespaceURI(),
                                   m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() ) );

        m_SchemaAnalyzer.setFilterList( filterList );
        encSchemWeak.findSchemaWeakness( m_SchemaAnalyzer );

        // 54 schemaweaknesses
        assertEquals( ( 54 * 4 ), encSchemWeak.getPossibleNumWeaks() ); // 2 (keyRef+ append)
        int newIdCounts = 0;
        int newKeyRefCounts = 0;
        int emptyRefCount = 0;
        // abuse the weakness
        for ( int i = 0; i < encSchemWeak.getPossibleNumWeaks(); ++i )
        {
            ElementAttackProperties attackProps = encEl.getAttackProperties();
            Document copyDoc = DomUtilities.createNewDomFromNode( doc.getDocumentElement() );
            Element copySigned = DomUtilities.findCorrespondingElement( copyDoc, attackProps.getSignedPart() );
            Element copyKey = DomUtilities.findCorrespondingElement( copyDoc, encKey.getEncryptedElement() );
            Element copyPayload = (Element) copyDoc.importNode( encEl.getEncryptedElement().cloneNode( true ), true );

            encSchemWeak.abuseWeakness( i, copyKey, copyPayload );
            log.trace( "### " + i + ")\n" + domToString( copyDoc, true ) + "\n" );

            assertNotNull( copySigned );
            assertNotNull( copyPayload );

            if ( !copyPayload.getAttribute( "Id" ).equals( encEl.getEncryptedElement().getAttribute( "Id" ) ) )
                newIdCounts++;

            List<Element> encKeyRefs = DomUtilities.findChildren( copyDoc, "DataReference", URI_NS_ENC, true );

            if ( 1 < encKeyRefs.size() || encKeyRefs.isEmpty() )
                newKeyRefCounts++;

            if ( encKeyRefs.isEmpty() )
                emptyRefCount++;

            List<Element> matched = DomUtilities.findChildren( copyDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matched.size() );

            List<Element> encComp = DomUtilities.findChildren( copySigned, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 1, encComp.size() );

            if ( matched.get( 0 ) == encComp.get( 0 ) )
            {
                assertEquals( matched.get( 0 ), encComp.get( 0 ) );
                assertEquals( matched.get( 1 ), copyPayload );
            }
            else
            {
                assertEquals( matched.get( 0 ), copyPayload );
                assertEquals( matched.get( 1 ), encComp.get( 0 ) );
            }
        }
        assertEquals( 2 * 54, newIdCounts );
        assertEquals( 2 * 54, newKeyRefCounts );
        assertEquals( 54, emptyRefCount );

    }

    // TODO: (signed) EncKey + (signed) EncData
    @Test
    public void testDetectSignedEncKeyEncDataSigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException,
        InvalidWeaknessException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/schema_encKey_sig_encData_sig.xml" );
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

        EncryptionSchemaWeakness encDataSchemWeak =
            (EncryptionSchemaWeakness) FactoryWeakness.generateWeakness( WeaknessType.SCHEMA_WEAKNESS, encEl, encKey );
        EncryptionSchemaWeakness encKeySchemWeak =
            (EncryptionSchemaWeakness) FactoryWeakness.generateWeakness( WeaknessType.SCHEMA_WEAKNESS, encKey, encKey );
        assertEquals( WrapModeEnum.WRAP_ENCKEY_WRAP_ENCDATA, encDataSchemWeak.getWrapMode() );
        assertEquals( WrapModeEnum.WRAP_ENCKEY_WRAP_ENCDATA, encKeySchemWeak.getWrapMode() );
        List<QName> filterList = new ArrayList<QName>();
        filterList.add( new QName( URI_NS_ENC, "EncryptedData" ) );
        filterList.add( new QName( URI_NS_DS, "SignedInfo" ) );
        filterList.add( new QName( URI_NS_DS, "SignatureValue" ) );
        filterList.add( new QName( m_SigManager.getPayloads().get( 0 ).getSignedElement().getNamespaceURI(),
                                   m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() ) );
        filterList.add( new QName( m_SigManager.getPayloads().get( 1 ).getSignedElement().getNamespaceURI(),
                                   m_SigManager.getPayloads().get( 1 ).getSignedElement().getLocalName() ) );

        m_SchemaAnalyzer.setFilterList( filterList );
        encDataSchemWeak.findSchemaWeakness( m_SchemaAnalyzer );
        encKeySchemWeak.findSchemaWeakness( m_SchemaAnalyzer );

        // 54 schemaweaknesses
        assertEquals( ( 54 * 4 ), encDataSchemWeak.getPossibleNumWeaks() ); // 3
        // (keyRef
        // append
        // only,
        // delete
        // all +
        // append,
        // delete all)
        // x 2
        // (change
        // ID ->
        // keyrefWeak,
        // keep
        // id ->
        // keyRefWeak)
        assertEquals( ( 54 * 2 ), encKeySchemWeak.getPossibleNumWeaks() );
        int newIdCounts = 0;
        int newKeyRefCounts = 0;

        // abuse the weakness
        /*
         * for (int i = 0; i < encDataSchemWeak.getPossibleNumWeaks(); ++i) { Document copyDoc =
         * DomUtilities.createNewDomFromNode(doc.getDocumentElement()); Element copySigned =
         * DomUtilities.findCorrespondingElement(copyDoc, encEl.getSignedPart()); Element copyPayload = (Element)
         * copyDoc.importNode(encEl.getEncryptedElement().cloneNode(true), true); encDataSchemWeak.abuseWeakness(i,
         * encEl.getSignedPart() , copyPayload); log.trace("### " + i + ")\n" + domToString(copyDoc, true) + "\n");
         * assertNotNull(copySigned); assertNotNull(copyPayload);
         * if(!copyPayload.getAttribute("Id").equals(encEl.getEncryptedElement(). getAttribute("Id"))) newIdCounts++;
         * List<Element> encKeyRefs = (List<Element>) DomUtilities.findChildren(copyDoc, "DataReference", URI_NS_ENC,
         * true); if(1<encKeyRefs.size()) newKeyRefCounts++; List<Element> matched = (List<Element>)
         * DomUtilities.findChildren(copyDoc, "EncryptedData", URI_NS_ENC, true); assertEquals(2, matched.size());
         * List<Element> encComp = (List<Element>) DomUtilities.findChildren(copySigned, "EncryptedData", URI_NS_ENC,
         * true); assertEquals(1, encComp.size()); if (matched.get(0) == encComp.get(0)) { assertEquals(matched.get(0),
         * encComp.get(0)); assertEquals(matched.get(1), copyPayload); } else { assertEquals(matched.get(0),
         * copyPayload); assertEquals(matched.get(1), encComp.get(0)); } for(int j=
         * 0;encKeySchemWeak.getPossibleNumWeaks()>j;j++) { Element copySigned =
         * DomUtilities.findCorrespondingElement(copyDoc, encEl.getSignedPart()); Element copyPayload = (Element)
         * copyDoc.importNode(encEl.getEncryptedElement().cloneNode(true), true); encSchemWeak.abuseWeakness(i,
         * encEl.getSignedPart() , copyPayload); log.trace("### " + i + ")\n" + domToString(copyDoc, true) + "\n");
         * assertNotNull(copySigned); assertNotNull(copyPayload);
         * if(!copyPayload.getAttribute("Id").equals(encEl.getEncryptedElement(). getAttribute("Id"))) newIdCounts++;
         * List<Element> encKeyRefs = (List<Element>) DomUtilities.findChildren(copyDoc, "DataReference", URI_NS_ENC,
         * true); if(1<encKeyRefs.size()) newKeyRefCounts++; List<Element> matched = (List<Element>)
         * DomUtilities.findChildren(copyDoc, "EncryptedData", URI_NS_ENC, true); assertEquals(2, matched.size());
         * List<Element> encComp = (List<Element>) DomUtilities.findChildren(copySigned, "EncryptedData", URI_NS_ENC,
         * true); assertEquals(1, encComp.size()); if (matched.get(0) == encComp.get(0)) { assertEquals(matched.get(0),
         * encComp.get(0)); assertEquals(matched.get(1), copyPayload); } else { assertEquals(matched.get(0),
         * copyPayload); assertEquals(matched.get(1), encComp.get(0)); } } } assertEquals(2*54,newIdCounts);
         * assertEquals(54,newKeyRefCounts);
         */

    }

    @Test
    public void testEncKeyInsideEncDataSigned()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException,
        InvalidWeaknessException
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
        assertEquals( 0, encInfo.getEncryptedKeyElements().size() );
        AbstractEncryptionElement encEl = encInfo.getEncryptedDataElements().get( 0 );

        EncryptionSchemaWeakness encSchemWeak =
            (EncryptionSchemaWeakness) FactoryWeakness.generateWeakness( WeaknessType.SCHEMA_WEAKNESS, encEl, null );
        assertEquals( WrapModeEnum.WRAP_ENC_ELEMENT, encSchemWeak.getWrapMode() );
        List<QName> filterList = new ArrayList<QName>();
        filterList.add( new QName( URI_NS_ENC, "EncryptedData" ) );
        filterList.add( new QName( URI_NS_DS, "SignedInfo" ) );
        filterList.add( new QName( URI_NS_DS, "SignatureValue" ) );
        // wrappingpositions in signed body do not use
        filterList.add( new QName( m_SigManager.getPayloads().get( 0 ).getSignedElement().getNamespaceURI(),
                                   m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() ) );

        m_SchemaAnalyzer.setFilterList( filterList );
        encSchemWeak.findSchemaWeakness( m_SchemaAnalyzer );

        // 60 schemaweaknesses
        assertEquals( ( 60 * 2 ), encSchemWeak.getPossibleNumWeaks() ); // 2 (change
                                                                        // ID, keep
                                                                        // id)
        int newIdCounts = 0;
        int newKeyRefCounts = 0;

        // abuse the weakness
        for ( int i = 0; i < encSchemWeak.getPossibleNumWeaks(); ++i )
        {
            ElementAttackProperties attackProps = encEl.getAttackProperties();
            Document copyDoc = DomUtilities.createNewDomFromNode( doc.getDocumentElement() );
            Element copySigned = DomUtilities.findCorrespondingElement( copyDoc, attackProps.getSignedPart() );
            Element copyPayload = (Element) copyDoc.importNode( encEl.getEncryptedElement().cloneNode( true ), true );

            encSchemWeak.abuseWeakness( i, attackProps.getSignedPart(), copyPayload );
            log.trace( "### " + i + ")\n" + domToString( copyDoc, true ) + "\n" );

            assertNotNull( copySigned );
            assertNotNull( copyPayload );

            if ( !copyPayload.getAttribute( "Id" ).equals( encEl.getEncryptedElement().getAttribute( "Id" ) ) )
                newIdCounts++;

            List<Element> encKeyRefs = DomUtilities.findChildren( copyDoc, "DataReference", URI_NS_ENC, true );

            if ( 1 < encKeyRefs.size() )
                newKeyRefCounts++;

            List<Element> matched = DomUtilities.findChildren( copyDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matched.size() );

            List<Element> encComp = DomUtilities.findChildren( copySigned, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 1, encComp.size() );

            if ( matched.get( 0 ) == encComp.get( 0 ) )
            {
                assertEquals( matched.get( 0 ), encComp.get( 0 ) );
                assertEquals( matched.get( 1 ), copyPayload );
            }
            else
            {
                assertEquals( matched.get( 0 ), copyPayload );
                assertEquals( matched.get( 1 ), encComp.get( 0 ) );
            }
        }
        assertTrue( 58 < newIdCounts );
        assertEquals( 0, newKeyRefCounts );

    }

    @Test
    public void testEncDataSignedWithoutId()
        throws FileNotFoundException, XPathExpressionException, SAXException, IOException, InvalidPayloadException,
        InvalidWeaknessException
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/case_encData_signed_no_id.xml" );
        DetectionManager detectManager = new DetectionManager( m_PipeLine, doc );
        detectManager.startDetection();
        DetectionReport detectReport = detectManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        SignatureInfo sigInfo = (SignatureInfo) detectReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        assertTrue( sigInfo.isSignature() );
        m_SigManager = sigInfo.getSignatureManager();
        assertEquals( 1, m_SigManager.getPayloads().size() );
        assertEquals( "Body", m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() );
        assertEquals( 0, encInfo.getEncryptedKeyElements().size() );
        AbstractEncryptionElement encEl = encInfo.getEncryptedDataElements().get( 0 );

        EncryptionSchemaWeakness encSchemWeak =
            (EncryptionSchemaWeakness) FactoryWeakness.generateWeakness( WeaknessType.SCHEMA_WEAKNESS, encEl, null );
        assertEquals( WrapModeEnum.WRAP_ENC_ELEMENT, encSchemWeak.getWrapMode() );

        List<QName> filterList = new ArrayList<QName>();
        filterList.add( new QName( URI_NS_ENC, "EncryptedData" ) );
        filterList.add( new QName( URI_NS_DS, "SignedInfo" ) );
        filterList.add( new QName( URI_NS_DS, "SignatureValue" ) );
        // wrappingpositions in signed body do not use
        filterList.add( new QName( m_SigManager.getPayloads().get( 0 ).getSignedElement().getNamespaceURI(),
                                   m_SigManager.getPayloads().get( 0 ).getSignedElement().getLocalName() ) );

        m_SchemaAnalyzer.setFilterList( filterList );
        encSchemWeak.findSchemaWeakness( m_SchemaAnalyzer );

        // 60 schemaweaknesses
        assertEquals( 66, encSchemWeak.getPossibleNumWeaks() ); // no id weakness
        int newIdCounts = 0;
        int newKeyRefCounts = 0;

        // abuse the weakness
        for ( int i = 0; i < encSchemWeak.getPossibleNumWeaks(); ++i )
        {
            ElementAttackProperties attackProps = encEl.getAttackProperties();
            Document copyDoc = DomUtilities.createNewDomFromNode( doc.getDocumentElement() );
            Element copySigned = DomUtilities.findCorrespondingElement( copyDoc, attackProps.getSignedPart() );
            Element copyPayload = (Element) copyDoc.importNode( encEl.getEncryptedElement().cloneNode( true ), true );

            encSchemWeak.abuseWeakness( i, attackProps.getSignedPart(), copyPayload );
            log.trace( "### " + i + ")\n" + domToString( copyDoc, true ) + "\n" );

            assertNotNull( copySigned );
            assertNotNull( copyPayload );

            if ( !copyPayload.getAttribute( "Id" ).equals( encEl.getEncryptedElement().getAttribute( "Id" ) ) )
                newIdCounts++;

            List<Element> encKeyRefs = DomUtilities.findChildren( copyDoc, "DataReference", URI_NS_ENC, true );

            if ( 1 < encKeyRefs.size() )
                newKeyRefCounts++;

            List<Element> matched = DomUtilities.findChildren( copyDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 2, matched.size() );

            List<Element> encComp = DomUtilities.findChildren( copySigned, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 1, encComp.size() );

            if ( matched.get( 0 ) == encComp.get( 0 ) )
            {
                assertEquals( matched.get( 0 ), encComp.get( 0 ) );
                assertEquals( matched.get( 1 ), copyPayload );
            }
            else
            {
                assertEquals( matched.get( 0 ), copyPayload );
                assertEquals( matched.get( 1 ), encComp.get( 0 ) );
            }
        }
        assertEquals( 0, newIdCounts );
        assertEquals( 0, newKeyRefCounts );

    }

    @Test
    public void testSignedEncKeyEncData()
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
        EncryptionSchemaWeakness encKeySchemWeak =
            (EncryptionSchemaWeakness) FactoryWeakness.generateWeakness( WeaknessType.SCHEMA_WEAKNESS, encKey, encKey );
        assertEquals( WrapModeEnum.WRAP_ENCKEY_ENCDATA, encKeySchemWeak.getWrapMode() );

        List<QName> filterList = new ArrayList<QName>();
        filterList.add( new QName( URI_NS_DS, "SignedInfo" ) );
        filterList.add( new QName( URI_NS_DS, "SignatureValue" ) );
        filterList.add( new QName( URI_NS_DS, "EncryptedKey" ) );

        m_SchemaAnalyzer.setFilterList( filterList );
        encKeySchemWeak.findSchemaWeakness( m_SchemaAnalyzer );

        // 132 schemaweaknesses
        assertEquals( ( 132 * 2 * 2 ), encKeySchemWeak.getPossibleNumWeaks() );
        int newIdCounts = 0;
        int newKeyRefCounts = 0;
        int newKeyRefURI = 0;

        // abuse the weakness
        for ( int i = 0; i < encKeySchemWeak.getPossibleNumWeaks(); ++i )
        {
            ElementAttackProperties attackProps = encKey.getAttackProperties();
            Document copyDoc = DomUtilities.createNewDomFromNode( doc.getDocumentElement() );
            Element copySigned = DomUtilities.findCorrespondingElement( copyDoc, attackProps.getSignedPart() );
            Element copyPayload = (Element) copyDoc.importNode( encKey.getEncryptedElement().cloneNode( true ), true );

            encKeySchemWeak.abuseWeakness( i, attackProps.getSignedPart(), copyPayload );
            log.trace( "### " + i + ")\n" + domToString( copyDoc, true ) + "\n" );

            assertNotNull( copySigned );
            assertNotNull( copyPayload );

            if ( !copyPayload.getAttribute( "Id" ).equals( encKey.getEncryptedElement().getAttribute( "Id" ) ) )
                newIdCounts++;

            List<Element> encKeyRefsPay = DomUtilities.findChildren( copyPayload, "DataReference", URI_NS_ENC, true );
            List<Element> encKeyRefsSigned =
                DomUtilities.findChildren( attackProps.getSignedPart(), "DataReference", URI_NS_ENC, true );

            if ( encKeyRefsPay.size() != encKeyRefsSigned.size() )
                newKeyRefCounts++;
            else if ( !encKeyRefsPay.get( 0 ).getAttribute( "URI" ).equals( encKeyRefsSigned.get( 0 ).getAttribute( "URI" ) ) )
                newKeyRefURI++;

            List<Element> matchedEncData = DomUtilities.findChildren( copyDoc, "EncryptedData", URI_NS_ENC, true );
            assertEquals( 1, matchedEncData.size() );

            List<Element> matchedEncKey = DomUtilities.findChildren( copyDoc, "EncryptedKey", URI_NS_ENC, true );
            assertEquals( 2, matchedEncKey.size() );

            assertEquals( "EncryptedKey", copySigned.getLocalName() );

            if ( matchedEncKey.get( 0 ) == copySigned )
            {
                assertEquals( matchedEncKey.get( 0 ), copySigned );
                assertEquals( matchedEncKey.get( 1 ), copyPayload );
            }
            else
            {
                assertEquals( matchedEncKey.get( 0 ), copyPayload );
                assertEquals( matchedEncKey.get( 1 ), copySigned );
            }
        }
        assertEquals( 132 * 2, newIdCounts );
        assertEquals( 132 * 2, newKeyRefCounts );
        assertEquals( 0, newKeyRefURI );

    }
}
