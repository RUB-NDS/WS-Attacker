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

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import wsattacker.library.xmlencryptionattack.attackengine.attackbase.CCAAttack;
import wsattacker.library.xmlencryptionattack.attackengine.attackbase.XMLEncryptionAttackBase;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.cbc.CBCAttacker;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.AOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.cbc.CBCOracle;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.concrete.pkcs1.PKCS1Oracle;
import wsattacker.library.xmlencryptionattack.attackengine.attacker.pkcs1.BleichenbacherAttacker;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AvoidedDocErrorInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants.Algorithm;
import static wsattacker.library.xmlencryptionattack.util.CryptoConstants.getAlgorithm;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.XMLEncryptionAttackMode;

/**
 * @author Dennis Kupser
 * @version 1.0
 * @created 18-Feb-2014 10:50:04
 */
public class AttackManager
{
    private final DetectionReport m_DetectionReport;

    private final Document m_InputFile;

    private final Document m_AvoidedFile;

    private final AbstractEncryptionElement m_AttackPayload;

    private final Algorithm m_EncryptionMethod;

    private XMLEncryptionAttackBase m_XMLEncryptionAttack;

    public AttackManager( DetectionReport detectRep, AttackConfig attackCfg, AOracle oracle )
        throws CryptoAttackException
    {
        this.m_DetectionReport = detectRep;
        this.m_InputFile = m_DetectionReport.getRawFile();
        AvoidedDocErrorInfo wrapInfo =
            (AvoidedDocErrorInfo) detectRep.getDetectionInfo( DetectFilterEnum.AVOIDDOCFILTER );
        this.m_AttackPayload = wrapInfo.getOriginalPayInput();
        this.m_AvoidedFile = wrapInfo.getAvoidedDocument();

        if ( null == m_AttackPayload )
            throw new IllegalArgumentException( "no attack payload set" );

        this.m_EncryptionMethod = getAlgorithm( m_AttackPayload.getEncryptionMethod() );

        if ( null == m_InputFile )
            throw new IllegalArgumentException( "input files not set" );

        initAttackObjects( attackCfg, oracle );
    }

    private void initAttackObjects( AttackConfig attackCfg, AOracle oracle )
        throws IllegalArgumentException, CryptoAttackException
    {
        if ( XMLEncryptionAttackMode.CBC_ATTACK == attackCfg.getXMLEncryptionAttack() )
        {
            if ( m_AttackPayload instanceof EncryptedDataElement )
            {
                if ( oracle instanceof CBCOracle )
                {
                    byte[] decodePay =
                        Base64.decodeBase64( m_AttackPayload.getCipherDataChild().getEncryptedData().getBytes() );
                    if ( null != m_EncryptionMethod )
                        m_XMLEncryptionAttack = new CBCAttacker( decodePay, oracle, m_EncryptionMethod.BLOCK_SIZE );
                    else
                        throw new IllegalArgumentException( "payload has no encryption method" );
                }
                else
                    throw new IllegalArgumentException( "no cbc oracle configured" );
            }
            else
                throw new IllegalArgumentException( "cbc attack configured but no encdata payload" );

        }
        else
        {
            if ( m_AttackPayload instanceof EncryptedKeyElement )
            {
                if ( oracle instanceof PKCS1Oracle )
                {
                    byte[] decodePay =
                        Base64.decodeBase64( m_AttackPayload.getCipherDataChild().getEncryptedData().getBytes() );
                    m_XMLEncryptionAttack = new BleichenbacherAttacker( decodePay, oracle );
                }
                else
                    throw new IllegalArgumentException( "no pkcs1 error oracle configured" );

            }
            else
                throw new IllegalArgumentException( "pkcs1 attack configured but no encKey payload" );
        }
    }

    public DetectionReport getDetectionReport()
    {
        return m_DetectionReport;
    }

    public Document getInputFile()
    {
        return m_InputFile;
    }

    public Document getAvoidedFile()
    {
        return m_AvoidedFile;
    }

    public XMLEncryptionAttackBase getXMLEncryptionAttack()
    {
        return m_XMLEncryptionAttack;
    }

    public byte[] executeAttack()
        throws CryptoAttackException
    {
        return m_XMLEncryptionAttack.executeAttack();
    }

    public AOracle getOracleofCCAAttacker()
    {
        return ( (CCAAttack) m_XMLEncryptionAttack ).getOracle();
    }

    public Algorithm getEncryptionMethod()
    {
        return m_EncryptionMethod;
    }
}