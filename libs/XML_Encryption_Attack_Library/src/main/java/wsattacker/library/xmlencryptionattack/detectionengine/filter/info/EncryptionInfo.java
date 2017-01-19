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
package wsattacker.library.xmlencryptionattack.detectionengine.filter.info;

import java.util.ArrayList;
import java.util.List;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;

public final class EncryptionInfo
    extends AbstractDetectionInfo
{
    private List<EncryptedDataElement> m_EncryptedDataElements;

    private List<EncryptedKeyElement> m_EncryptedKeyElements;

    public List<EncryptedDataElement> getEncryptedDataElements()
    {
        return m_EncryptedDataElements;
    }

    public void setEncryptedDataElements( List<EncryptedDataElement> encryptedDataElements )
    {
        this.m_EncryptedDataElements = encryptedDataElements;
    }

    public List<EncryptedKeyElement> getEncryptedKeyElements()
    {
        return m_EncryptedKeyElements;
    }

    public void setEncryptedKeyElements( List<EncryptedKeyElement> encryptedKeyElements )
    {
        this.m_EncryptedKeyElements = encryptedKeyElements;
    }

    public EncryptionInfo( DetectFilterEnum infoType )
    {
        this.m_EncryptedDataElements = new ArrayList<EncryptedDataElement>();
        this.m_EncryptedKeyElements = new ArrayList<EncryptedKeyElement>();
        this.mInfoType = infoType;
    }

    public void addEncryptedKeyElements( EncryptedKeyElement encKey )
    {
        m_EncryptedKeyElements.add( encKey );
    }

    public void addEncryptedDataElements( EncryptedDataElement encDatta )
    {
        m_EncryptedDataElements.add( encDatta );
    }

}