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
package wsattacker.library.intelligentdos.position;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.position.MatcherPositionIterator.Finding;

/**
 * @author Christian Altmeier
 */
public class MatcherPositionTest
{
    private final String xmlWithPlaceholder = "<soapenv:Envelope $$PAYLOADATTR$$>"
        + "   <soapenv:Header $$PAYLOADATTR$$>$$PAYLOADELEMENT$$</soapenv:Header>"
        + "   <soapenv:Body $$PAYLOADATTR$$>" + "      <cxf:celsiusToFarenheit>" + "         <arg0>1</arg0>"
        + "      </cxf:celsiusToFarenheit>" + "   $$PAYLOADELEMENT$$</soapenv:Body>"
        + "$$PAYLOADELEMENT$$</soapenv:Envelope>";

    @Test
    public void createContentTest()
    {
        Finding finding = new Finding();
        finding.start = 18;
        finding.end = 33;
        finding.placeholder = "$$PAYLOADATTR$$";

        MatcherPosition matcherPosition = new MatcherPosition( xmlWithPlaceholder, finding );
        assertThat( matcherPosition.createPlaceholder( PayloadPosition.ATTRIBUTE ),
                    is( "<soapenv:Envelope $$PAYLOADATTR$$>" + "   <soapenv:Header ></soapenv:Header>"
                        + "   <soapenv:Body >" + "      <cxf:celsiusToFarenheit>" + "         <arg0>1</arg0>"
                        + "      </cxf:celsiusToFarenheit>" + "   </soapenv:Body>" + "</soapenv:Envelope>" ) );
    }

    @Test
    public void equalsTest()
    {
        Finding finding = new Finding();
        finding.start = 18;
        finding.end = 33;
        finding.placeholder = "$$PAYLOADATTR$$";
        MatcherPosition matcherPosition = new MatcherPosition( xmlWithPlaceholder, finding );

        assertThat( matcherPosition.equals( null ), is( Boolean.FALSE ) );
        assertThat( matcherPosition.equals( matcherPosition ), is( Boolean.TRUE ) );
        assertThat( matcherPosition.equals( Integer.valueOf( 1 ) ), is( Boolean.FALSE ) );

        Finding finding2 = new Finding();
        finding2.start = 18;
        finding2.end = 33;
        finding2.placeholder = "$$PAYLOADATTR$$";
        MatcherPosition findingEQ = new MatcherPosition( xmlWithPlaceholder, finding2 );
        assertThat( matcherPosition.equals( findingEQ ), is( Boolean.TRUE ) );

        Finding finding3 = new Finding();
        finding2.start = 20;
        finding2.end = 35;
        finding2.placeholder = "$$PAYLOADATTR$$";
        MatcherPosition findingNEQ = new MatcherPosition( xmlWithPlaceholder, finding3 );
        assertThat( matcherPosition.equals( findingNEQ ), is( Boolean.FALSE ) );
    }

}
