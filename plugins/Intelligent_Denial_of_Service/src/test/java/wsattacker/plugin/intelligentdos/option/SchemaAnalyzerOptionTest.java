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
package wsattacker.plugin.intelligentdos.option;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.beans.PropertyChangeEvent;

import org.junit.Test;

import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.main.testsuite.CurrentRequest;

/**
 * @author Christian Altmeier
 */
public class SchemaAnalyzerOptionTest
{

    private final SchemaAnalyzer schemaAnalyzer = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );

    private final String xml =
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:my=\"http://my\">\n"
            + "   <soapenv:Header/>\n" + "   <soapenv:Body>\n" + "      <my:reverse>\n"
            + "         <my:stringToRevers>?</my:stringToRevers>\n" + "      </my:reverse>\n" + "   </soapenv:Body>\n"
            + "</soapenv:Envelope>";

    @Test
    public void abc()
    {
        SchemaAnalyzerOption sao = new SchemaAnalyzerOption( null, xml, schemaAnalyzer );
        PropertyChangeEvent evt = new PropertyChangeEvent( this, CurrentRequest.PROP_WSDLREQUESTCONTENT, xml, xml );
        sao.propertyChange( evt );
        assertThat( sao.getValue(),
                    is( "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:my=\"http://my\" $$PAYLOADATTR$$>\n"
                        + "   <soapenv:Header $$PAYLOADATTR$$>$$PAYLOADELEMENT$$</soapenv:Header>\n"
                        + "   <soapenv:Body $$PAYLOADATTR$$>\n"
                        + "      <my:reverse>\n"
                        + "         <my:stringToRevers>?</my:stringToRevers>\n"
                        + "      </my:reverse>\n"
                        + "   $$PAYLOADELEMENT$$</soapenv:Body>\n" + "$$PAYLOADELEMENT$$</soapenv:Envelope>" ) );
    }
}
