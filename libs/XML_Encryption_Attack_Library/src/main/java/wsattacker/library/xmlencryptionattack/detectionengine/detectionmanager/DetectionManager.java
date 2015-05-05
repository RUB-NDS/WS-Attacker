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

import java.util.Iterator;
import java.util.List;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.signature.ReferenceElement;
import wsattacker.library.signatureWrapping.util.signature.SignatureElement;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.TimestampInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.KeyInfoElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.KeyReferenceElement;
import wsattacker.library.xmlencryptionattack.timestampelement.TimestampBase;

public class DetectionManager
{
    private Pipeline m_Pipeline;

    private DetectionReport m_DetectionReport;

    private Document m_InputFile = null;

    public final static Logger LOG = Logger.getLogger( DetectionManager.class );

    public Document getInputFile()
    {
        return m_InputFile;
    }

    public void setInputFile( Document inputFile )
    {
        this.m_InputFile = inputFile;
    }

    public DetectionReport getDetectionReport()
    {
        return m_DetectionReport;
    }

    public void setDetectionReport( DetectionReport detectionReport )
    {
        this.m_DetectionReport = detectionReport;
    }

    public DetectionManager( Pipeline pipeline, Document doc )
    {
        this.m_Pipeline = pipeline;
        this.m_InputFile = doc;
        m_DetectionReport = new DetectionReport();
        m_DetectionReport.setRawFile( doc );
    }

    public void startDetection()
        throws InvalidPayloadException
    {
        AbstractDetectionFilter detectFilter = null;
        AbstractDetectionInfo detectedInfo = null;
        Iterator<AbstractDetectionFilter> it = m_Pipeline.getPipelineIterator();

        while ( it.hasNext() )
        {
            detectFilter = it.next();
            if ( null != m_InputFile ) // all filter use same input
            {
                detectFilter.setInputDocument( m_InputFile );
            }
            detectedInfo = detectFilter.process();
            m_DetectionReport.addDetectionInfo( detectedInfo.getInfoType(), detectedInfo );
        }

        if ( null != m_DetectionReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER ) )
        {
            if ( null != m_DetectionReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER ) )
            {
                detectSignedEncryptionParts();
            }

            if ( null != m_DetectionReport.getDetectionInfo( DetectFilterEnum.TIMESTAMPFILTER ) )
            {
                detectSignedTimeStamps();
            }
        }
    }

    public Pipeline getPipeline()
    {
        return m_Pipeline;
    }

    public void setPipeline( Pipeline pipeline )
    {
        this.m_Pipeline = pipeline;
    }

    public void addFilterToPipeline( AbstractDetectionFilter filter )
    {
        this.m_Pipeline.addFilerToPipline( filter );
    }

    private void detectSignedEncryptionParts()
        throws InvalidPayloadException
    {
        List<SignatureElement> sigList =
            ( (SignatureInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER ) ).getSignatureElements();
        // get relation between signaturemanager->payloadlist and the detected encrypted parts
        detectSignedEncryptionKeyParts( sigList );
        detectSignedEncryptionDataParts( sigList );
    }

    private void detectSignedEncryptionDataParts( List<SignatureElement> sigList )
    {
        List<EncryptedDataElement> encDataList =
            ( (EncryptionInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER ) ).getEncryptedDataElements();
        // encData only (without a keyElement)
        for ( int i = 0; i < encDataList.size(); i++ )
        {
            for ( int j = 0; j < sigList.size(); j++ )
            {
                if ( encDataList.get( i ) instanceof EncryptedDataElement )
                {
                    List<ReferenceElement> sigRefs = sigList.get( j ).getReferences();
                    ElementAttackProperties encAttackProp = null;
                    short containModeData = 0;
                    for ( int k = 0; k < sigRefs.size(); k++ )
                    {
                        containModeData =
                            sigRefs.get( j ).getReferencedElement().compareDocumentPosition( ( (EncryptedDataElement) encDataList.get( i ) ).getEncryptedElement() );

                        if ( 0 == containModeData || ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & containModeData ) )
                            || ( 0 < ( Node.DOCUMENT_POSITION_CONTAINS & containModeData ) ) )
                        {
                            KeyInfoElement keyInfo = null;
                            encAttackProp = ( (EncryptedDataElement) encDataList.get( i ) ).getAttackProperties();
                            encAttackProp.setSignedPart( sigRefs.get( k ).getReferencedElement() );
                            encAttackProp.setSignMode( containModeData );
                            keyInfo = ( (EncryptedDataElement) encDataList.get( i ) ).getKeyInfoElement();

                            if ( null != keyInfo )
                            {
                                EncryptedKeyElement encKey = keyInfo.getEncryptedKeyElement();

                                if ( null != encKey )
                                {
                                    encAttackProp = encKey.getAttackProperties();
                                    encAttackProp.setSignMode( containModeData );
                                    encAttackProp.setSignedPart( sigRefs.get( k ).getReferencedElement() );
                                    LOG.info( "EncryptedDataOnly with EncryptedKey in KeyInfo detected. Signed mode : "
                                        + containModeData );
                                    continue;
                                }
                            }

                            LOG.info( "EncryptedDataOnly detected with signed mode : " + containModeData );
                        }
                    }
                }
                else
                    throw new IllegalArgumentException( "No valid EncryptionElement!" );
            }
        }
    }

    private void detectSignedEncryptionKeyParts( List<SignatureElement> sigList )
    {
        List<EncryptedKeyElement> encKeyList =
            ( (EncryptionInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER ) ).getEncryptedKeyElements();
        // keyelements with their keydatas
        for ( int i = 0; i < encKeyList.size(); i++ )
        {
            for ( int j = 0; j < sigList.size(); j++ )
            {
                if ( encKeyList.get( i ) instanceof EncryptedKeyElement )
                {
                    // get signaturerefs
                    ElementAttackProperties encAttackProp = null;
                    List<ReferenceElement> sigRefs = sigList.get( j ).getReferences();
                    List<AbstractRefElement> encRefs =
                        ( (EncryptedKeyElement) encKeyList.get( i ) ).getReferenceElementList();
                    short containModeKey = 0;
                    for ( int k = 0; k < sigRefs.size(); k++ )
                    {
                        containModeKey =
                            sigRefs.get( k ).getReferencedElement().compareDocumentPosition( encKeyList.get( i ).getEncryptedElement() );
                        // encKey signed??
                        if ( 0 == containModeKey || ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & containModeKey ) )
                            || ( 0 < ( Node.DOCUMENT_POSITION_CONTAINS & containModeKey ) ) )
                        {
                            encAttackProp = ( (EncryptedKeyElement) encKeyList.get( i ) ).getAttackProperties();
                            encAttackProp.setSignedPart( sigRefs.get( k ).getReferencedElement() );
                            encAttackProp.setSignMode( containModeKey );
                            LOG.info( "Signed EncryptedKey detected with signed mode : " + containModeKey );
                        }
                        // encDatas signed??
                        short containModeRefs = 0;
                        for ( int l = 0; l < encRefs.size(); l++ )
                        {
                            containModeRefs =
                                sigRefs.get( k ).getReferencedElement().compareDocumentPosition( encRefs.get( l ).getReferredElement() );
                            // is node encData signed?...is part of signed reference?
                            if ( 0 == containModeRefs
                                || ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & containModeRefs ) )
                                || ( 0 < ( Node.DOCUMENT_POSITION_CONTAINS & containModeRefs ) ) )
                            {
                                if ( encRefs.get( l ) instanceof DataReferenceElement )
                                {
                                    encAttackProp =
                                        ( (DataReferenceElement) encRefs.get( l ) ).getRefEncData().getAttackProperties();
                                    encAttackProp.setSignedPart( sigRefs.get( k ).getReferencedElement() );
                                    encAttackProp.setSignMode( containModeRefs );
                                    LOG.info( "Signed EncryptedData with EncKey detected with signed mode : "
                                        + containModeRefs );
                                }
                                else if ( encRefs.get( i ) instanceof KeyReferenceElement )
                                {
                                    throw new IllegalArgumentException( " keyreference not supported yet!" );
                                }
                            }
                        }
                    }
                }
                else
                    throw new IllegalArgumentException( "No valid EncryptionElement!" );
            }
        }

    }

    // TODO: generally detect for all elements
    private void detectSignedTimeStamps()
    {
        final List<SignatureElement> sigList =
            ( (SignatureInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER ) ).getSignatureElements();
        final TimestampInfo timeStampInfo =
            ( (TimestampInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.TIMESTAMPFILTER ) );
        TimestampBase timestamp = timeStampInfo.getTimestamp();

        if ( null != timestamp )
        {
            Element timestampElement = timestamp.getDetectionElement();

            for ( int j = 0; j < sigList.size(); j++ )
            {
                List<ReferenceElement> sigRefs = sigList.get( j ).getReferences();

                short containModeStamp = 0;
                for ( int k = 0; k < sigRefs.size(); k++ )
                {
                    containModeStamp =
                        sigRefs.get( k ).getReferencedElement().compareDocumentPosition( timestampElement );

                    if ( 0 == containModeStamp || ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & containModeStamp ) )
                        || ( 0 < ( Node.DOCUMENT_POSITION_CONTAINS & containModeStamp ) ) )
                    {
                        timestamp.setIsSigned( true );
                        LOG.info( "Signed Timestamp detected." );
                        return;
                    }
                }
            }
            timestamp.setIsSigned( false );
            timestamp.setTimeStampPayloads( timestamp.getDetectionElement() );
            LOG.info( "Detected Timestamp not signed." );
        }
    }

}
