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

package wsattacker.library.xmlencryptionattack.timestampelement;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.DetectionElementIF;

/**
 * @author Dennis
 */
public abstract class TimestampBase
    implements DetectionElementIF
{
    protected Element m_TimestampElement = null;

    protected Element m_TimestampPayload = null;

    protected int m_TimeDifference = 0;

    protected boolean m_IsSigned = false;

    protected boolean m_IsMillisecondTime = false;

    public abstract void updateTimeStamp( Document doc );

    public abstract void setTimeStampPayloads( Element payload );

    public boolean isMillisecondTime()
    {
        return m_IsMillisecondTime;
    }

    public void setIsMillisecondTime( boolean isMillisecondTime )
    {
        this.m_IsMillisecondTime = isMillisecondTime;
    }

    public int getTimeDifference()
    {
        return m_TimeDifference;
    }

    public void setTimeDifference( int timeDifference )
    {
        this.m_TimeDifference = timeDifference;
    }

    @Override
    public boolean isSigned()
    {
        return m_IsSigned;
    }

    @Override
    public void setIsSigned( boolean isSigned )
    {
        this.m_IsSigned = isSigned;
    }

    @Override
    public Element getDetectionPayElement()
    {
        return m_TimestampPayload;
    }

    @Override
    public void setDetectionPayElement( Element detectPayElement )
    {
        this.m_TimestampPayload = detectPayElement;
    }

    @Override
    public Element getDetectionElement()
    {
        return m_TimestampElement;
    }

    @Override
    public void setDetectionElement( Element detectElement )
    {
        this.m_TimestampElement = detectElement;
    }
}
