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
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.signature.SignatureElement;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;

public final class SignatureInfo
    extends AbstractDetectionInfo
{
    private List<SignatureElement> m_SignatureElements;

    private SignatureManager m_SignatureManager = null;

    private List<Payload> m_UsedPayloads = null;

    public SignatureInfo( DetectFilterEnum infoType )
    {
        this.m_SignatureElements = new ArrayList<SignatureElement>();
        this.mInfoType = infoType;
    }

    public List<Payload> getUsedPayloads()
    {
        return m_UsedPayloads;
    }

    public void setUsedPayloads( List<Payload> usedPayloads )
    {
        this.m_UsedPayloads = usedPayloads;
    }

    public SignatureManager getSignatureManager()
    {
        return m_SignatureManager;
    }

    public void setSignatureManager( SignatureManager signatureManager )
    {
        this.m_SignatureManager = signatureManager;
        setUsedPayloads( m_SignatureManager.getPayloads() );
    }

    public void setSignatureElements( List<SignatureElement> sigList )
    {
        this.m_SignatureElements = sigList;
    }

    public List<SignatureElement> getSignatureElements()
    {
        return m_SignatureElements;
    }

    public boolean isSignature()
    {
        return !m_SignatureElements.isEmpty();
    }

}