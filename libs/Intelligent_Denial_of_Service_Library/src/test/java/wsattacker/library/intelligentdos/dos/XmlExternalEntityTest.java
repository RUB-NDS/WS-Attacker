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
package wsattacker.library.intelligentdos.dos;

import javax.xml.parsers.ParserConfigurationException;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.testhelper.IDoSTestHelper;

/**
 * @author Christian Altmeier
 */
public class XmlExternalEntityTest
{

    private final XmlExternalEntity xmlExternalEntity = new XmlExternalEntity();

    @Test
    public void hasFurther()
    {
        assertThat( xmlExternalEntity.hasFurtherParams(), is( true ) );
    }

    @Test
    public void oneParam()
    {
        assertThat( xmlExternalEntity.hasFurtherParams(), is( true ) );
        xmlExternalEntity.nextParam();
        assertThat( xmlExternalEntity.hasFurtherParams(), is( false ) );
    }

    @Test
    public void two()
    {
        xmlExternalEntity.setExternalEntities( new String[] { "a", "b" } );

        for ( int i = 0; i < 2; i++ )
        {
            assertThat( xmlExternalEntity.hasFurtherParams(), is( true ) );
            xmlExternalEntity.nextParam();
        }

        assertThat( xmlExternalEntity.hasFurtherParams(), is( false ) );
    }

    @Test( expected = IllegalArgumentException.class )
    public void notAllowedPayloadPosition()
    {
        assertThat( xmlExternalEntity.hasFurtherParams(), is( true ) );
        xmlExternalEntity.nextParam();

        xmlExternalEntity.getTamperedRequest( "", PayloadPosition.ATTRIBUTE );
    }

    @Test
    public void tampered()
        throws ParserConfigurationException
    {

        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        xmlExternalEntity.setExternalEntities( new String[] { "\"abc\"", "\"/dev/urandom\"" } );

        assertThat( xmlExternalEntity.hasFurtherParams(), is( true ) );
        xmlExternalEntity.nextParam();

        String tampered =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<!DOCTYPE requestType [ <!ENTITY attackEntity SYSTEM \"abc\">]>";
        assertThat( xmlExternalEntity.getTamperedRequest( xml, payloadPosition ), startsWith( tampered ) );
        assertThat( xmlExternalEntity.getTamperedRequest( xml, payloadPosition ), containsString( ">&attackEntity;<" ) );

        assertThat( xmlExternalEntity.hasFurtherParams(), is( true ) );
        xmlExternalEntity.nextParam();

        tampered =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<!DOCTYPE requestType [ <!ENTITY attackEntity SYSTEM \"/dev/urandom\">]>";
        assertThat( xmlExternalEntity.getTamperedRequest( xml, payloadPosition ), startsWith( tampered ) );
        assertThat( xmlExternalEntity.getTamperedRequest( xml, payloadPosition ), containsString( ">&attackEntity;<" ) );

        assertThat( xmlExternalEntity.hasFurtherParams(), is( false ) );
    }

    @Test
    public void untampered()
        throws ParserConfigurationException
    {
        PayloadPosition payloadPosition = PayloadPosition.ELEMENT;

        String xml = IDoSTestHelper.createTestString( payloadPosition );

        xmlExternalEntity.setExternalEntities( new String[] { "\"abc\"", "\"/dev/urandom\"" } );

        assertThat( xmlExternalEntity.hasFurtherParams(), is( true ) );
        xmlExternalEntity.nextParam();

        String tamperedRequest = xmlExternalEntity.getTamperedRequest( xml, payloadPosition );
        String untamperedRequest = xmlExternalEntity.getUntamperedRequest( xml, payloadPosition );

        String referece =
            "><!-- cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlExternalEntity.hasFurtherParams(), is( true ) );
        xmlExternalEntity.nextParam();

        tamperedRequest = xmlExternalEntity.getTamperedRequest( xml, payloadPosition );
        untamperedRequest = xmlExternalEntity.getUntamperedRequest( xml, payloadPosition );

        referece =
            "><!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --></";
        assertThat( untamperedRequest, containsString( referece ) );

        // Test length
        assertThat( untamperedRequest.length(), is( tamperedRequest.length() ) );

        assertThat( xmlExternalEntity.hasFurtherParams(), is( false ) );
    }
}
