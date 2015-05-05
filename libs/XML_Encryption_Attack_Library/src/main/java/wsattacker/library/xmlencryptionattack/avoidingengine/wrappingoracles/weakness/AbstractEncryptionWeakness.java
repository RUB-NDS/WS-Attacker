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

import java.util.List;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.WrapModeEnum;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;

public abstract class AbstractEncryptionWeakness
{
    protected EncryptedKeyElement m_EncKey = null;

    protected AbstractEncryptionElement m_EncPay = null;

    protected WrapModeEnum m_WrapMode = null;

    protected int m_PossibleWeaks;

    public abstract void abuseWeakness( int index, Element encKey, Element payloadElement );

    public abstract int getPossibleNumWeaks();

    public WrapModeEnum getWrapMode()
    {
        return m_WrapMode;
    }

    public void setWrapMode( WrapModeEnum encSignedMode )
    {
        this.m_WrapMode = encSignedMode;
    }

    protected void determineEncSignMode( AbstractEncryptionElement encPay, EncryptedKeyElement encKey )
    {
        Element encPayElement = encPay.getEncryptedElement();
        if ( null == encPay )
            throw new IllegalArgumentException( "encPay element must not be null" );

        if ( null == encKey )
        {
            m_WrapMode = WrapModeEnum.WRAP_ENC_ELEMENT;
        }
        else if ( encPay.getEncryptedElement().getLocalName().equals( encKey.getEncryptedElement().getLocalName() ) )
        {
            ElementAttackProperties encKeyDataAttackProp = null;
            int idxEncDataPay = ( (EncryptedKeyElement) encKey ).getWrappingEncDataIndex();
            List<AbstractRefElement> encRefs = encKey.getReferenceElementList();
            // Ref handling over encDataElements => only wrapperpos + id has to change
            encKeyDataAttackProp =
                ( (DataReferenceElement) encRefs.get( idxEncDataPay ) ).getRefEncData().getAttackProperties();
            if ( encKeyDataAttackProp.isSigned() || encKeyDataAttackProp.isAdditionalWrap() )
                m_WrapMode = WrapModeEnum.WRAP_ENCKEY_WRAP_ENCDATA;
            else
                // modified encKey pay handle like encElementOnly (searching for better solution)
                m_WrapMode = WrapModeEnum.WRAP_ENCKEY_ENCDATA;
        }
        else if ( encPayElement.getLocalName().equals( "EncryptedData" )
            && ( !encKey.getAttackProperties().isSigned() && !encKey.getAttackProperties().isAdditionalWrap() ) )
        {
            m_WrapMode = WrapModeEnum.ENCKEY_WRAP_ENCDATA;
        }
        else if ( encPayElement.getLocalName().equals( "EncryptedData" )
            && ( encKey.getAttackProperties().isSigned() || encKey.getAttackProperties().isAdditionalWrap() ) )
        {
            m_WrapMode = WrapModeEnum.WRAP_ENCKEY_WRAP_ENCDATA;
        }
        else
            throw new IllegalArgumentException( "No valid EncSignMode detected in document!" );
    }

}
