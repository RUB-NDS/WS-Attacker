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
package wsattacker.plugin.xmlencryptionattack.option;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.xmlencryptionattack.attackengine.AttackConfig;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.PKCS1AttackConfig;
import wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory.SimStringStrategy;
import static wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.strategy.PKCS1StrategyFactory.PKCS1Strategy.DIRECT;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectionManager;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.FactoryFilter;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.Pipeline;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.EncryptionInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.OracleMode;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.XMLEncryptionAttackMode;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.plugin.option.AbstractOptionMultiFiles;
import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.plugin.PluginOptionContainer;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.main.plugin.option.OptionSimpleMultiFiles;
import wsattacker.main.plugin.option.OptionSoapAction;
import wsattacker.plugin.xmlencryptionattack.XMLEncryptionAttack;

public final class OptionManagerEncryption
    implements CurrentRequestContentChangeObserver, PropertyChangeListener
{
    private static final Logger LOG = Logger.getLogger( OptionManagerEncryption.class );

    private XMLEncryptionAttack m_Plugin;

    private DetectionManager m_DetectionManager;

    private final OptionSoapAction m_OptionSoapAction;

    private final OptionSimpleBoolean m_OptionUseSchema;

    private final OptionSimpleMultiFiles m_OptionSchemaFiles;

    private OptionServerErrorBehaviour m_OptionServerResponse;

    private final List<AbstractEncryptionElement> m_OptionPayloadList;

    private OptionPayloadEncryption m_OptionEncPays = null;

    private final AttackConfig m_AttackCfg;

    private boolean m_IsInProgress = false;

    private static final OptionManagerEncryption INSTANCE = new OptionManagerEncryption();

    private final Pipeline m_PipeLine;

    public static OptionManagerEncryption getInstance()
    {
        return INSTANCE;
    }

    public XMLEncryptionAttack getPlugin()
    {
        return m_Plugin;
    }

    public void setPlugin( XMLEncryptionAttack plugin )
    {
        if ( this.m_Plugin != null )
        {
            this.m_Plugin.getPluginOptions().addPropertyChangeListener( this );
        }
        this.m_Plugin = plugin;
        if ( plugin != null )
        {
            this.m_Plugin.getPluginOptions().addPropertyChangeListener( this );
            this.m_Plugin.getPluginOptions().setOptions( addConfigOptions() );
        }
        plugin.setAttackCfg( m_AttackCfg );
    }

    public DetectionManager getDetectioManager()
    {
        return m_DetectionManager;
    }

    /**
     * Initialization method.
     */
    private OptionManagerEncryption()
    {
        this.m_OptionSoapAction = new OptionSoapAction( "Change\nAction?", "Allows to change the SoapAction Header." );
        this.m_OptionSchemaFiles =
            new OptionSimpleMultiFiles( "Used\nSchema\nfiles",
                                        "Set the Schema Files.\nSoap11, Soap12, WSA, WSSE, WSU, DS and XPathFilter2\nare included by default." );
        this.m_OptionUseSchema = new OptionSimpleBoolean( "Schema?", true, "Use XML Schema." );
        this.m_OptionPayloadList = new ArrayList<AbstractEncryptionElement>();
        this.m_OptionServerResponse = null;
        PKCS1AttackConfig pKCS1AttackCFG = new PKCS1AttackConfig();
        this.m_AttackCfg = new AttackConfig();
        m_AttackCfg.setPKCS1AttackCfg( pKCS1AttackCFG );
        initAttackCfg();
        m_PipeLine = new Pipeline();
    }

    public void initAttackCfg()
    {
        /* Default */
        m_AttackCfg.setOracleMode( OracleMode.ERROR_ORACLE );
        m_AttackCfg.setWrappingMode( WrappingAttackMode.NO_WRAP );
        m_AttackCfg.setXMLEncryptionAttack( XMLEncryptionAttackMode.CBC_ATTACK );
        m_AttackCfg.setSimStringStrategyType( SimStringStrategy.DICE_COEFF );
        m_AttackCfg.setChosenAttackPayload( null );
        m_AttackCfg.setChosenWrapPayload( null );
        m_AttackCfg.setStringCmpThresHold( AttackConfig.DEFAULT_STRING_CMP_THRESHOLD );
        m_AttackCfg.setStringCmpWrappThreshold( AttackConfig.DEFAULT_STRING_CMP_WRAP_ERROR_THRESHOLD );
        m_AttackCfg.getPKCS1AttackCfg().setServerRSAPubKey( null );
        m_AttackCfg.getPKCS1AttackCfg().setPKCS1Strategy( DIRECT );

    }

    public OptionServerErrorBehaviour getOptionServerResponse()
    {
        return m_OptionServerResponse;
    }

    private Logger log()
    {
        return Logger.getLogger( getClass() );
    }

    @Override
    public void currentRequestContentChanged( String newContent, String oldContent )
    {
        if ( !m_IsInProgress )
        {
            m_IsInProgress = true;

            if ( !oldContent.equals( "" ) )
                log().trace( "Current Request Content Changed" );

            Document domDoc;
            try
            {
                domDoc = DomUtilities.stringToDom( newContent );
            }
            catch ( SAXException e )
            {
                if ( null != m_DetectionManager )
                    m_DetectionManager.setInputFile( null );
                m_IsInProgress = false;
                return;
            }

            Document copyDomDoc = DomUtilities.createNewDomFromNode( domDoc.getDocumentElement() );

            addPayloads( copyDomDoc );
            List<AbstractOption> allOptions = addConfigOptions();
            if ( m_Plugin != null )
            {
                m_Plugin.getPluginOptions().setOptions( allOptions );
            }
            m_IsInProgress = false;
        }
    }

    private void addPayloads( Document domDoc )
    {
        DetectionReport detectReport = null;
        m_PipeLine.removeAllFilerFromPipline();
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.ENCRYPTIONFILTER ) );
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.SIGNATUREFILTER ) );
        m_PipeLine.addFilerToPipline( FactoryFilter.createFilter( DetectFilterEnum.TIMESTAMPFILTER ) );
        m_DetectionManager = handleDetection( domDoc );
        detectReport = m_DetectionManager.getDetectionReport();
        EncryptionInfo encInfo = (EncryptionInfo) detectReport.getDetectionInfo( DetectFilterEnum.ENCRYPTIONFILTER );
        List<EncryptedKeyElement> encKeyList = encInfo.getEncryptedKeyElements();
        List<EncryptedDataElement> encDataList = encInfo.getEncryptedDataElements();

        for ( int i = 0; i < m_OptionPayloadList.size(); ++i )
        {
            AbstractEncryptionElement option = m_OptionPayloadList.get( i );
            ElementAttackProperties attackProps = option.getAttackProperties();
            attackProps.removePropertyChangeListener( this );
        }
        m_OptionPayloadList.clear();

        for ( EncryptedKeyElement payload : encKeyList )
        {
            List<AbstractRefElement> keyDatas = payload.getReferenceElementList();
            ElementAttackProperties attackProps = payload.getAttackProperties();
            if ( attackProps.isSigned() )
            {
                attackProps.setWrappingPayloadElement( payload.getEncryptedElement() );
            }

            for ( int j = 0; keyDatas.size() > j; j++ )
            {
                EncryptedDataElement encData = ( (DataReferenceElement) keyDatas.get( j ) ).getRefEncData();
                ElementAttackProperties attackPropsData = encData.getAttackProperties();
                if ( attackPropsData.isSigned() )
                    attackPropsData.setWrappingPayloadElement( encData.getEncryptedElement() );
            }

            attackProps.addPropertyChangeListener( this );
            m_OptionPayloadList.add( payload );
        }

        for ( EncryptedDataElement payload : encDataList )
        {
            ElementAttackProperties attackProps = payload.getAttackProperties();
            if ( attackProps.isSigned() )
            {
                attackProps.setWrappingPayloadElement( payload.getEncryptedElement() );
            }
            attackProps.addPropertyChangeListener( this );
            m_OptionPayloadList.add( payload );
        }

        this.m_OptionEncPays = new OptionPayloadEncryption( m_OptionPayloadList, this );
        this.m_OptionServerResponse = new OptionServerErrorBehaviour( m_AttackCfg, detectReport );
        m_OptionServerResponse.addPropertyChangeListener( OptionServerErrorBehaviour.PROP_SERVERBEHAVE, this );
        if ( null != m_OptionServerResponse )
            m_OptionServerResponse.removePropertyChangeListener( OptionServerErrorBehaviour.PROP_SERVERBEHAVE, this );

        initAttackCfg();
    }

    public DetectionReport getDetectReport()
    {
        return m_DetectionManager.getDetectionReport();
    }

    /**
     * If no curent request is available, the SignatureManager must be notified.
     */
    @Override
    public void noCurrentRequestcontent()
    {
        if ( m_IsInProgress )
        {
            return;
        }
        m_IsInProgress = true;
        log().trace( "No Current Message" );
        if ( null != m_DetectionManager )
            m_DetectionManager.setInputFile( null );
        clearOptions();
        m_IsInProgress = false;
    }

    /**
     * This methods add the default config options to the OptionManagerEncryption. Those are: - Option for changing the
     * SOAPAction. - Option for aborting the attack if one XSW message is accepted. - Option to not use any XML Schema.
     * - Option to selected XML Schema files. - Option to add a search string. - The View Button - The Payload-Chooser
     * Combobox
     */
    private List<AbstractOption> addConfigOptions()
    {
        List<AbstractOption> result;
        if ( getPlugin() == null )
        {
            log().debug( "No plugin set?" );
            result = Collections.<AbstractOption> emptyList();
        }
        else
        {
            List<AbstractOption> newOptions = new ArrayList<AbstractOption>();
            log().info( "Adding OptionSoapAction" );
            newOptions.add( 0, m_OptionSoapAction );
            log().info( "Adding OptionNoSchema" );
            newOptions.add(1, m_OptionUseSchema );
            log().info( "Adding OptionSchemaFiles" );
            newOptions.add( 2, m_OptionSchemaFiles );
            if ( m_OptionPayloadList.size() > 0 )
            {
                log().info( "Adding Enc Pays " );
                newOptions.add( 3, m_OptionEncPays );
                log().info( "Adding Server Error Response table " );
                newOptions.add( 4, m_OptionServerResponse );
            }
            result = newOptions;

        }
        return result;
    }

    /**
     * This function is only needed due to a GUI Bug in WS-Attacker which does not allow to put an AbstractOption at a
     * specific position. With this function, you can pop AbstractOptions up to one specific one, than add the needed
     * Options, and afterwards re-add the popped one putOptions.
     *
     * @param needle
     * @return
     */
    public List<AbstractOption> popOptionsUpTo( AbstractOption needle )
    {
        List<AbstractOption> result = new ArrayList<AbstractOption>();
        PluginOptionContainer container = getPlugin().getPluginOptions();
        if ( !container.contains( needle ) )
        {
            return result;
        }
        while ( container.size() > 0 )
        {
            AbstractOption last = container.getByIndex( container.size() - 1 );
            if ( last == needle )
            {
                break;
            }
            container.remove( last );
            result.add( last );
        }
        log().info( "Popped: " + result.toString() );
        return result;
    }

    /**
     * This function is only needed due to a GUI Bug in WS-Attacker which does not allow to put an AbstractOption at a
     * specific position. With this function, you can pop AbstractOptions up to one specific one, than add the needed
     * Options, and afterwards re-add the popped one putOptions.
     *
     * @param needle
     * @return
     */
    public void putOptions( List<AbstractOption> optionList )
    {
        log().info( "Put: " + optionList.toString() );
        PluginOptionContainer container = getPlugin().getPluginOptions();
        for ( int i = optionList.size() - 1; i >= 0; --i )
        {
            container.add( optionList.get( i ) );
        }
    }

    /**
     * Clear all options consecutively.
     */
    public void clearOptions()
    {
        if ( getPlugin() == null )
        {
            log().debug( "No plugin set?" );
        }
        else
        {
            log().info( "Clearing Options.." );
            PluginOptionContainer container = getPlugin().getPluginOptions();
            while ( container.size() > 0 )
            {
                container.remove( container.getByIndex( 0 ) );
            }
        }
    }

    /**
     * Handler if an option value is changed. Changes, e.g. the concrete showed PayloadOption.
     */
    @Override
    public void propertyChange( PropertyChangeEvent pce )
    {
        PluginOptionContainer container = getPlugin().getPluginOptions();
        if ( pce.getSource() instanceof OptionPayloadEncryption )
        {
            m_Plugin.checkState();
        }
        else if ( pce.getSource() == m_OptionSchemaFiles )
        {
            m_Plugin.setUsedSchemaFiles( m_OptionSchemaFiles.getFiles() );

        }
        else if ( pce.getSource() == m_OptionUseSchema )
        {
            log().info( "Remove Schema Files Option" );
            if ( !m_OptionUseSchema.isOn() && container.contains( m_OptionSchemaFiles ) )
            {
                container.remove( m_OptionSchemaFiles );
                m_Plugin.setSchemaAnalyzerDepdingOnOption();
            }
            else if ( !container.contains( m_OptionSchemaFiles ) )
            {
                log().info( "Add Schema Files Option" );
                container.add(1 + container.indexOf(m_OptionUseSchema ), m_OptionSchemaFiles );
            }
        }
        getPlugin().checkState();
    }

    public OptionSoapAction getOptionSoapAction()
    {
        return m_OptionSoapAction;
    }

    public AbstractOptionMultiFiles getOptionSchemaFiles()
    {
        return m_OptionSchemaFiles;
    }

    public OptionSimpleBoolean getOptionUseSchema()
    {
        return m_OptionUseSchema;
    }

    private DetectionManager handleDetection( Document attackDoc )
    {
        DetectionManager detectManager = null;
        detectManager = new DetectionManager( m_PipeLine, attackDoc );
        try
        {
            detectManager.startDetection();
        }
        catch ( InvalidPayloadException ex )
        {
            LOG.error( ex );
        }
        return detectManager;
    }

    private void setPayload()
    {
        DetectionReport detectReport = m_DetectionManager.getDetectionReport();
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
        }
    }
}
