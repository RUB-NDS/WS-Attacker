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
package wsattacker.library.xmlencryptionattack.attackengine.oracle.base.response;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */

@XmlAccessorType( XmlAccessType.FIELD )
@XmlRootElement( name = "OracleResponse" )
public class OracleResponse
{

    /**
     * based on the response string the oracle can decide, if the request was VALID, INVALID, or if the response is not
     * known yet
     */
    public enum Result
    {
        VALID, INVALID, UNDEFINED
    };

    /**
     * result
     */
    private Result result;

    /**
     * the whole response string (maybe needed for debugging purposes?)
     */
    private String response;

    private String request;

    public String getRequest()
    {
        return request;
    }

    public void setRequest( String request )
    {
        this.request = request;
    }

    public Result getResult()
    {
        return result;
    }

    public void setResult( Result result )
    {
        this.result = result;
    }

    public String getResponse()
    {
        return response;
    }

    public void setResponse( String response )
    {
        this.response = response;
    }
}
