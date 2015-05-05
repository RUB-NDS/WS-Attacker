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
package wsattacker.library.xmlencryptionattack.detectionengine.filter.base;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;

public abstract class AbstractDetectionFilter
{
    protected AbstractDetectionInfo m_OutputFilter = null;

    protected Document m_InputFilter = null;

    protected DetectFilterEnum mFilterType;

    protected ServerSendCommandIF m_ServerSendCmd;

    public final static Logger LOG = Logger.getLogger( AbstractDetectionFilter.class );

    public abstract AbstractDetectionInfo process();

    public void setInputDocument( Document doc )
    {
        this.m_InputFilter = doc;
    }

    public DetectFilterEnum getFilterType()
    {
        return mFilterType;
    }

    public Document getInputDocument()
    {
        return m_InputFilter;
    }

    public AbstractDetectionFilter()
    {

    }

    public ServerSendCommandIF getServerSendCmd()
    {
        return m_ServerSendCmd;
    }

    public void setServerSendCmd( ServerSendCommandIF m_ServerSendCmd )
    {
        this.m_ServerSendCmd = m_ServerSendCmd;
    }

}