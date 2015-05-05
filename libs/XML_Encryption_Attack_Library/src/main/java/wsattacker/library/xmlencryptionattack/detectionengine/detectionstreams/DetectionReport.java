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
package wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams;

import java.util.EnumMap;
import java.util.Map;
import org.w3c.dom.Document;
import wsattacker.library.xmlencryptionattack.attackengine.oracle.base.mode.OracleResponseCollector;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.AbstractDetectionInfo;

public final class DetectionReport
{
    private Document m_RawFile;

    private Document m_AvoidedFile;

    private OracleResponseCollector m_ErrorResponseTab = null;

    private final Map<DetectFilterEnum, AbstractDetectionInfo> m_DetectionInfo;

    public DetectionReport()
    {
        m_DetectionInfo = new EnumMap<DetectFilterEnum, AbstractDetectionInfo>( DetectFilterEnum.class );
    }

    public void addDetectionInfo( DetectFilterEnum type, AbstractDetectionInfo detectInfo )
    {
        m_DetectionInfo.put( type, detectInfo );
    }

    public void removeDetectionInfo( DetectFilterEnum type )
    {
        m_DetectionInfo.remove( type );
    }

    public AbstractDetectionInfo getDetectionInfo( DetectFilterEnum type )
    {
        return m_DetectionInfo.get( type );
    }

    public Document getRawFile()
    {
        return m_RawFile;
    }

    public void setRawFile( Document xmlFile )
    {
        this.m_RawFile = xmlFile;
    }

    public OracleResponseCollector getErrorResponseTab()
    {
        return m_ErrorResponseTab;
    }

    public void setErrorResponseTab( OracleResponseCollector errorResponseTab )
    {
        this.m_ErrorResponseTab = errorResponseTab;
    }

}