/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2014 Christian Mainka
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
package wsattacker.http.transport;

import java.util.*;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class SoapResponse
{

    private List<HttpHeader> headers;

    private String body;

    private String statusLine;

    public SoapResponse()
    {
        headers = new ArrayList<HttpHeader>();
    }

    public List<HttpHeader> getHeaders()
    {
        return headers;
    }

    public void setHeaders( List<HttpHeader> headers )
    {
        this.headers = headers;
    }

    public String getBody()
    {
        return body;
    }

    public void setBody( String body )
    {
        this.body = body;
    }

    public String getStatusLine()
    {
        return statusLine;
    }

    public void setStatusLine( String statusLine )
    {
        this.statusLine = statusLine;
    }
}
