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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.util.CryptoConstants.Algorithm;

public final class AvoidedDocErrorInfo
    extends AbstractDetectionInfo
{
    private AbstractEncryptionElement m_OriginalPayInput = null;

    private Element m_ErrorPayOutput = null;

    private Algorithm m_AlgoOfSymmtricBlockCipher = null;

    private Document m_ErrorDocument = null;

    private Document m_AvoidedDocument = null;

    public Document getErrorDocument()
    {
        return m_ErrorDocument;
    }

    public void setErrorDocument( Document errorDocument )
    {
        this.m_ErrorDocument = errorDocument;
    }

    public AvoidedDocErrorInfo( DetectFilterEnum infoType )
    {
        this.mInfoType = infoType;
    }

    public AbstractEncryptionElement getOriginalPayInput()
    {
        return m_OriginalPayInput;
    }

    public void setOriginalPayInput( AbstractEncryptionElement originalInput )
    {
        this.m_OriginalPayInput = originalInput;
    }

    public Element getErrorPayOutput()
    {
        return m_ErrorPayOutput;
    }

    public void setErrorPayOutput( Element errorOutput )
    {
        this.m_ErrorPayOutput = errorOutput;
    }

    public void setAvoidedDocument( Document avoidedDocument )
    {
        m_AvoidedDocument = avoidedDocument;
    }

    public Document getAvoidedDocument()
    {
        return m_AvoidedDocument;
    }

    public Algorithm getAlgoOfSymmtricBlockCipher()
    {
        return m_AlgoOfSymmtricBlockCipher;
    }

    public void setAlgoOfSymmtricBlockCipher( Algorithm algoOfSymmtricBlockCipher )
    {
        this.m_AlgoOfSymmtricBlockCipher = algoOfSymmtricBlockCipher;
    }
}
