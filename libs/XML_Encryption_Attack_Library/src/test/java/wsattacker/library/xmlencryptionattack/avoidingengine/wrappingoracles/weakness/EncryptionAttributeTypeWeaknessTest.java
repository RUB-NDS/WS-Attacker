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
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
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
public class EncryptionAttributeTypeWeaknessTest
{

    private SignatureManager m_SigManager;

    private Pipeline m_PipeLine;

    private SchemaAnalyzer m_SchemaAnalyzer;

    private static Logger log = Logger.getLogger( EncryptionAttributeIdWeaknessTest.class );

    public EncryptionAttributeTypeWeaknessTest()
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

        EncryptionAttributeTypeWeakness encTypeWeak =
            (EncryptionAttributeTypeWeakness) FactoryWeakness.generateWeakness( WeaknessType.ATTR_TYPE_WEAKNESS,
                                                                                encData, encKey );
        // assertEquals( WrapModeEnum.WRAP_ENCKEY_ENCDATA, encTypeWeak.getWrapMode() );

        assertEquals( 2, encTypeWeak.getPossibleNumWeaks() );

        // abuse the weakness
        for ( int i = 0; i < encTypeWeak.getPossibleNumWeaks(); ++i )
        {
            Document copyDoc = DomUtilities.createNewDomFromNode( doc.getDocumentElement() );
            Element copyEncData = DomUtilities.findCorrespondingElement( copyDoc, encData.getEncryptedElement() );
            Element copyPayload = (Element) copyDoc.importNode( encData.getEncryptedElement().cloneNode( true ), true ); // payLoad
                                                                                                                         // encKey

            encTypeWeak.abuseWeakness( i, null, copyPayload );
            log.trace( "### " + i + ")\n" + domToString( copyDoc, true ) + "\n" );

            assertNotNull( copyEncData );
            assertNotNull( copyPayload );

            if ( 0 == i )
            {
                assertTrue( copyPayload.getAttributeNode( "Type" ).getValue().equals( copyEncData.getAttributeNode( "Type" ).getValue() ) );
            }
            else
            {
                assertTrue( copyEncData.getAttributeNode( "Type" ).getValue().equals( ENC_TYPE_CONTENT ) );
                assertTrue( copyPayload.getAttributeNode( "Type" ).getValue().equals( ENC_TYPE_ELEMENT ) );
            }
        }
    }

}
