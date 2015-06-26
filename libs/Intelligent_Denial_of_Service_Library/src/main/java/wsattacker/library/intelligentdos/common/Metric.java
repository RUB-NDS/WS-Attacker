/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.library.intelligentdos.common;

import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.lang3.StringUtils;

/**
 * @author Christian Altmeier
 */
@XmlRootElement
public class Metric
{

    private long duration;

    private String content = "";

    public long getDuration()
    {
        return duration;
    }

    public void setDuration( long duration )
    {
        this.duration = duration;
    }

    public String getContent()
    {
        return content;
    }

    public void setContent( String content )
    {
        this.content = content;
    }

    /**
     * Check for empty Response
     * 
     * @return
     */
    public boolean isEmptyResponse()
    {
        return StringUtils.isEmpty( content );
    }

    /**
     * Check for Connection reset
     * 
     * @return
     */
    public boolean isConnectionReset()
    {
        return StringUtils.contains( content, "Connection reset" )
            || StringUtils.contains( content, "Software caused connection abort: recv failed" );
    }

    /**
     * Check for read timed out
     * 
     * @return
     */
    public boolean isReadTimedOut()
    {
        return StringUtils.contains( content, "timed out" );
    }

    /**
     * Check for SOAP-Fault SOAP-Fault check by finding end of closing Tag "Fault>"
     * 
     * @return
     */
    public boolean isSOAPFault()
    {
        return content.contains( "Fault>" ) || content.contains( "fault>" );
    }

}
