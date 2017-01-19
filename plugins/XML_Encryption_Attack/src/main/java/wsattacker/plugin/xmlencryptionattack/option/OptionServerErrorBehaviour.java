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

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import javax.xml.bind.JAXBException;
import javax.xml.xpath.XPathExpressionException;
import org.xml.sax.SAXException;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.library.xmlencryptionattack.attackengine.AttackConfig;
import wsattacker.library.xmlencryptionattack.attackengine.CryptoAttackException;
import static wsattacker.library.xmlencryptionattack.attackengine.Utility.getPubKeyFromCert;
import static wsattacker.library.xmlencryptionattack.attackengine.Utility.getPubKeyFromKeyFile;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.OracleResponseCollector;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response.OracleResponse;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.util.JAXBOResponseHandler;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.testsuite.TestSuite;
import wsattacker.plugin.xmlencryptionattack.WebServiceSendCommand;
import wsattacker.plugin.xmlencryptionattack.XMLEncryptionAttack;
import wsattacker.plugin.xmlencryptionattack.serverbehaviour.ServerErrMsgSendFunc;
import wsattacker.plugin.xmlencryptionattack.serverbehaviour.gui.ServerBehaviourGUI;

public class OptionServerErrorBehaviour
    extends AbstractOption
{

    private final OracleResponseCollector m_ServerErrorTab = new OracleResponseCollector();

    private final AttackConfig m_AttackCfg;

    private final DetectionReport m_DetectionReport;

    public static final String PROP_SERVERBEHAVE = "serverBehave";

    private static final long serialVersionUID = 1L;

    private Thread m_MessageThread;

    private ServerBehaviourGUI m_OptionTableGUI;

    private boolean m_IsPKCS1WithEncData = false;

    private ServerErrMsgSendFunc m_ServerErrorFunc = null;

    public OptionServerErrorBehaviour( AttackConfig attackcfg, DetectionReport detectReport )
    {
        super( "Error Table", "Display the error Table." );
        // wrapping muss einbezogen werden!!!
        this.m_DetectionReport = detectReport;
        this.m_DetectionReport.setErrorResponseTab( m_ServerErrorTab );
        this.m_AttackCfg = attackcfg;
    }

    public AttackConfig getAttackCfg()
    {
        return m_AttackCfg;
    }

    @Override
    public OptionGUI createOptionGUI()
    {
        return m_OptionTableGUI = new ServerBehaviourGUI( getCollection().getOwnerPlugin(), this );
    }

    public void updateProgressBar( int progressStep )
    {
        m_OptionTableGUI.updateProgressBar( progressStep );
    }

    @Override
    /**
     * Nothing to do
     */
    public boolean isValid( String value )
    {
        return true;
    }

    @Override
    /**
     * Nothing to do
     */
    public void parseValue( String value )
    {
    }

    @Override
    /**
     * Nothing to do
     */
    public String getValueAsString()
    {
        return getName();
    }

    public List<OracleResponse> getResponseData()
    {
        return m_ServerErrorTab.getData();
    }

    public void SaveDataToFile( File file )
        throws IOException, JAXBException
    {
        // save button for gui
        JAXBOResponseHandler.marshal( m_ServerErrorTab.getData(), file );
    }

    public void LoadDataFromFile( File file )
    {
        try
        {
            m_ServerErrorTab.setData( JAXBOResponseHandler.unmarshal( file ) );
            m_DetectionReport.setErrorResponseTab( m_ServerErrorTab );
            m_OptionTableGUI.initTable();
            firePropertyChange( PROP_SERVERBEHAVE, null, null );
        }
        catch ( JAXBException e )
        {
            e.printStackTrace();
        }
    }

    public void getServerBehaviour()
        throws IOException, JAXBException, CryptoAttackException
    {
        final WsdlRequest currentWsdlRequest = TestSuite.getInstance().getCurrentRequest().getWsdlRequest();
        ServerSendCommandIF serCmdnew = new WebServiceSendCommand( currentWsdlRequest );
        m_ServerErrorFunc = new ServerErrMsgSendFunc( m_AttackCfg, m_DetectionReport, this, serCmdnew );
        m_ServerErrorTab.setCompareThreshold( m_AttackCfg.getStringCmpThresHold() );
        m_ServerErrorFunc.setIsPKCS1WithEncData( m_IsPKCS1WithEncData );
        m_MessageThread = new Thread( m_ServerErrorFunc );
        m_MessageThread.start();

    }

    private org.apache.log4j.Logger log()
    {
        return org.apache.log4j.Logger.getLogger( getClass() );
    }

    public void setGUIButtonState( boolean b )
    {
        m_OptionTableGUI.setBtnsState( b );
    }

    public void updateServerErrOption( OracleResponse serverResp, AbstractEncryptionElement pay )
        throws SAXException, XPathExpressionException
    {
        boolean isNewError = false;
        if ( m_ServerErrorTab.isIgnorePayloadResponse() )
        {
            if ( !m_ServerErrorTab.checkIsRequestResponse( serverResp, pay ) )
            {
                isNewError = m_ServerErrorTab.add( serverResp );
            }
        }
        else
        {
            isNewError = m_ServerErrorTab.add( serverResp );
        }

        if ( isNewError )
        {
            m_OptionTableGUI.updateTable( serverResp );
        }
    }

    public void deleteAllErrorTabDatas()
    {
        m_ServerErrorTab.getData().clear();
        m_OptionTableGUI.initTable();
        ( (XMLEncryptionAttack) getCollection().getOwnerPlugin() ).checkState();
    }

    public void setCertServer( File certtificate )
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
        CertificateException
    {
        m_AttackCfg.getPKCS1AttackCfg().setServerRSAPubKey( (RSAPublicKey) getPubKeyFromCert( certtificate ) );
    }

    public void setPubKeyServer( File pubKey )
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
        CertificateException
    {
        m_AttackCfg.getPKCS1AttackCfg().setServerRSAPubKey( (RSAPublicKey) getPubKeyFromKeyFile( pubKey ) );
    }

    public void stopSendingMessages()
    {
        if ( null != m_ServerErrorFunc )
        {
            m_ServerErrorFunc.stop();
            m_MessageThread.stop();
        }
        setGUIButtonState( true );
    }

    public void abortSendingMessages()
    {
        if ( null != m_ServerErrorFunc )
        {
            m_ServerErrorFunc.stop();
        }
    }

    public void setIsPKCS1WithEncData( boolean state )
    {
        m_IsPKCS1WithEncData = state;
    }

    public void setIsIgnoreRequestResponse( boolean state )
    {
        m_ServerErrorTab.setIsIgnorePayloadResponse( state );
    }

}
