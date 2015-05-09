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

package wsattacker.library.xmlencryptionattack.attackengine;

import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.PKCS1AttackConfig;
import wsattacker.library.xmlencryptionattack.util.SimStringStrategyFactory.SimStringStrategy;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.OracleMode;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.XMLEncryptionAttackMode;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.CryptoTechnique;

/**
 * @author Dennis
 */
public final class AttackConfig
{
    public static final double DEFAULT_STRING_CMP_THRESHOLD = 0.9;

    public static final double DEFAULT_STRING_CMP_WRAP_ERROR_THRESHOLD = 0.9;

    private OracleMode m_OracleMode = null;

    private SimStringStrategy m_SimStringStrategyType = null;

    private XMLEncryptionAttackMode m_XMLEncryptionAttackMode = null;

    private WrappingAttackMode m_WrappingMode = null;

    private AbstractEncryptionElement m_ChosenAttackPayload = null;

    private AbstractEncryptionElement m_ChosenWrapPayload = null;

    private double m_StringCmpThresHold = DEFAULT_STRING_CMP_THRESHOLD;

    private double m_StringCmpWrappErrThreshold = DEFAULT_STRING_CMP_WRAP_ERROR_THRESHOLD;

    private PKCS1AttackConfig m_PKCS1AttackCfg;

    private boolean m_IsEncTypeWeakness = false;

    public boolean isEncTypeWeakness()
    {
        return m_IsEncTypeWeakness;
    }

    public void setIsEncTypeWeakness( boolean isEncTypeWeakness )
    {
        this.m_IsEncTypeWeakness = isEncTypeWeakness;
    }

    public PKCS1AttackConfig getPKCS1AttackCfg()
    {
        return m_PKCS1AttackCfg;
    }

    public void setPKCS1AttackCfg( PKCS1AttackConfig pKCS1AttackCfg )
    {
        this.m_PKCS1AttackCfg = pKCS1AttackCfg;
    }

    public double getStringCmpWrappErrThreshold()
    {
        return m_StringCmpWrappErrThreshold;
    }

    public void setStringCmpWrappThreshold( double stringCmpWrappErrThres )
    {
        this.m_StringCmpWrappErrThreshold = stringCmpWrappErrThres;
    }

    public double getStringCmpThresHold()
    {
        return m_StringCmpThresHold;
    }

    public void setStringCmpThresHold( double stringCmpThresHold )
    {
        this.m_StringCmpThresHold = stringCmpThresHold;
    }

    public AbstractEncryptionElement getChosenWrapPayload()
    {
        return m_ChosenWrapPayload;
    }

    public void setChosenWrapPayload( AbstractEncryptionElement chosenWrapPayload )
    {
        this.m_ChosenWrapPayload = chosenWrapPayload;
    }

    public WrappingAttackMode getWrappingMode()
    {
        return m_WrappingMode;
    }

    public void setWrappingMode( WrappingAttackMode wrappingMode )
    {
        this.m_WrappingMode = wrappingMode;
    }

    public AbstractEncryptionElement getChosenAttackPayload()
    {
        return m_ChosenAttackPayload;
    }

    public void setChosenAttackPayload( AbstractEncryptionElement userChosenEncPayload )
    {
        // special case if enckey in encdata
        if ( userChosenEncPayload instanceof EncryptedDataElement )
        {
            if ( null != userChosenEncPayload.getKeyInfoElement() )
            {
                if ( null != userChosenEncPayload.getKeyInfoElement().getEncryptedKeyElement() )
                {
                    if ( CryptoTechnique.ASYMMETRIC == m_XMLEncryptionAttackMode.getCryptoTechnique() )
                    {
                        this.m_ChosenAttackPayload = userChosenEncPayload.getKeyInfoElement().getEncryptedKeyElement();
                        m_ChosenAttackPayload.getAttackProperties().setAttackPayloadElement( m_ChosenAttackPayload.getEncryptedElement() );
                        return;
                    }
                }
            }
        }
        this.m_ChosenAttackPayload = userChosenEncPayload;
    }

    public AttackConfig()
    {

    }

    public SimStringStrategy getSimStringStrategyType()
    {
        return m_SimStringStrategyType;
    }

    public void setSimStringStrategyType( SimStringStrategy simStringStrategyType )
    {
        this.m_SimStringStrategyType = simStringStrategyType;
    }

    public OracleMode getOracleMode()
    {
        return m_OracleMode;
    }

    public void setOracleMode( OracleMode oracleMode )
    {
        this.m_OracleMode = oracleMode;
    }

    public XMLEncryptionAttackMode getXMLEncryptionAttack()
    {
        return m_XMLEncryptionAttackMode;
    }

    public void setXMLEncryptionAttack( XMLEncryptionAttackMode xmlEncryptionAttack )
    {
        this.m_XMLEncryptionAttackMode = xmlEncryptionAttack;
    }

}
