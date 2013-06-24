/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.util;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.submit.transports.http.WsdlResponse;
import wsattacker.main.composition.testsuite.RequestResponsePair;

/**
 * Never used in production, just a util class for Testsetup!
 */
public class RequestResponsePairTest implements RequestResponsePair {
    
    private WsdlRequest request;
    private WsdlResponse response;
    
    @Override
    public WsdlRequest getWsdlRequest(){
	return request;
    }
    
    @Override
    public WsdlResponse getWsdlResponse(){
	return response;
    }
    
    public void setWsdlRequest(WsdlRequest request){
	this.request = request;
    }
    
    public void setWsdlResponse(WsdlResponse response){
	this.response = response;
    }    
}
