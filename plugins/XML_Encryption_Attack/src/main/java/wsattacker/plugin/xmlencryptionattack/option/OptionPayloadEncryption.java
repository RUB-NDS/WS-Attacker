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
import java.beans.PropertyChangeSupport;
import java.util.List;
import org.apache.log4j.Logger;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.TimestampInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.timestampelement.TimestampElement;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.plugin.xmlencryptionattack.gui.OptionPayloadEncGUI;

public class OptionPayloadEncryption
    extends AbstractOption
    implements PropertyChangeListener
{

    private final transient PropertyChangeSupport m_PropertyChangeSupport = new java.beans.PropertyChangeSupport( this );

    final static private Logger LOG = Logger.getLogger( OptionPayloadEncryption.class );

    private final List<AbstractEncryptionElement> m_Payloads;

    private final TimestampElement m_Timestamp;

    private final OptionManagerEncryption m_OptionManager;

    public static final String NO_ENCKEY_ELEMENTS = "no extern encrypted key elements";

    public static final String NO_ENCDATA_ELEMENTS = "no encrypted data elements";

    public static final String PROP_ISADD_WRAPP = "addWrapp";

    public List<AbstractEncryptionElement> getPayloads()
    {
        return m_Payloads;
    }

    public OptionPayloadEncryption( List<AbstractEncryptionElement> payloads, OptionManagerEncryption optionManager )
    {
        super( "Encryption Payloads Options", "Management of detected encrypted elements" );

        this.m_Payloads = payloads;
        this.m_OptionManager = optionManager;
        TimestampInfo timeInfo =
            (TimestampInfo) m_OptionManager.getDetectioManager().getDetectionReport().getDetectionInfo( DetectFilterEnum.TIMESTAMPFILTER );
        this.m_Timestamp = timeInfo.getTimestamp();
        ElementAttackProperties attackProps = null;
        for ( int i = 0; m_Payloads.size() > i; i++ )
        {
            attackProps = m_Payloads.get( i ).getAttackProperties();
            attackProps.addPropertyChangeListener( this );
        }
    }

    public TimestampElement getTimestamp()
    {
        return m_Timestamp;
    }

    public boolean hasPayload( int index )
    {
        if ( m_Payloads == null )
        {
            return false;
        }
        else
        {
            ElementAttackProperties attackProps = m_Payloads.get( index ).getAttackProperties();
            if ( null != attackProps.getAttackPayloadElement() || null != attackProps.getWrappingPayloadElement() )
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    @Override
    public boolean isValid( String value )
    {
        for ( int i = 0; m_Payloads.size() > i; )
        {
            if ( !m_Payloads.get( i ).isValid( value ) )
                return false;
        }

        return true;
    }

    /**
     * Returns the GUI component for the OptionPayloadEncryption used by the WS-Attacker.
     * 
     * @return
     */
    @Override
    public OptionGUI createOptionGUI()
    {
        LOG.trace( getName() + ": " + "GUI Requested" );
        m_OptionManager.initAttackCfg();
        return new OptionPayloadEncGUI( this, getCollection().getOwnerPlugin() );
    }

    @Override
    public void parseValue( String value )
    {
        return;
    }

    @Override
    public String getValueAsString()
    {
        return "";
    }

    @Override
    public void propertyChange( PropertyChangeEvent pce )
    {
        final String property = pce.getPropertyName();
        if ( PROP_ISADD_WRAPP.equals( property ) )
        {
            Object oldValue = pce.getOldValue();
            Object newValue = pce.getNewValue();
            firePropertyChange( PROP_ISADD_WRAPP, oldValue, newValue );
        }
    }

    public void setSigWrappPayload( AbstractEncryptionElement payElement )
    {
        final SignatureInfo sigInfo =
            (SignatureInfo) m_OptionManager.getDetectioManager().getDetectionReport().getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        List<Payload> pays = sigInfo.getSignatureManager().getPayloads();
        ElementAttackProperties attackProps = payElement.getAttackProperties();

        /*
         * for ( int i = 0; pays.size() > i; i++ ) { if ( pays.get( i ).isTimestamp() ) pays.remove( i ); }
         */
        for ( int i = 0; pays.size() > i; i++ )
        {
            pays.get( i ).removeValue();
        }
        sigInfo.setUsedPayloads( pays );

        if ( payElement instanceof EncryptedKeyElement )
        {
            int encDataIdx = ( (EncryptedKeyElement) payElement ).getWrappingEncDataIndex();
            List<AbstractRefElement> refList = ( (EncryptedKeyElement) payElement ).getReferenceElementList();
            EncryptedDataElement encData = ( (DataReferenceElement) refList.get( encDataIdx ) ).getRefEncData();
            ElementAttackProperties attackPropsData = encData.getAttackProperties();

            for ( int i = 0; pays.size() > i; i++ )
            {
                if ( attackProps.isSigned() )
                {
                    if ( pays.get( i ).getSignedElement().isEqualNode( attackProps.getSignedPart() ) )
                    {
                        pays.get( i ).setValue( pays.get( i ).getValue() );
                    }
                }

                if ( attackPropsData.isSigned() )
                {
                    if ( pays.get( i ).getSignedElement().isEqualNode( attackPropsData.getSignedPart() ) )
                    {
                        pays.get( i ).setValue( pays.get( i ).getValue() );
                    }
                }
            }
        }
        else if ( payElement instanceof EncryptedDataElement )
        {
            if ( attackProps.isSigned() )
            {
                for ( int i = 0; pays.size() > i; i++ )
                {
                    if ( pays.get( i ).getSignedElement().isEqualNode( attackProps.getSignedPart() ) )
                    {
                        pays.get( i ).setValue( pays.get( i ).getValue() );
                    }
                }
            }
        }
        // wrappingElement in original document -> "copy" in wrapping attackdoc
        // attackDocu for wrapping attacks -> new "copy" wrapping element -> attack element for encryption attack
        // in encryption attack -> wrappingDoc => "avoided file" -> copy of avoided file + ciphervalue of chosen
        // encryption attack
        // copy of "avoided file" is the last document for encryption attack
    }

    public void setIsAddWrap( boolean isAddWrap, AbstractEncryptionElement payElement )
    {
        payElement.getAttackProperties().setIsAdditionalWrap( isAddWrap );
        if ( isAddWrap )
        {
            payElement.getAttackProperties().setWrappingPayloadElement( payElement.getEncryptedElement() );
        }
        else
        {
            payElement.getAttackProperties().setWrappingPayloadElement( null );
        }
    }
}
