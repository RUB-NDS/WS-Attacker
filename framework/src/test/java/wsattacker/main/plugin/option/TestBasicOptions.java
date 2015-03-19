/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.main.plugin.option;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;

public class TestBasicOptions
{

    @Test
    public void optionInteger()
    {
        AbstractOptionInteger iOpt = new OptionSimpleInteger( "Integer", 0, "Integer Test" );
        assertTrue( "Legal Value", iOpt.isValid( "0" ) );
        assertTrue( "Legal Value", iOpt.isValid( "1" ) );
        assertTrue( "Legal Value", iOpt.isValid( "9999" ) );
        assertTrue( "Legal Value", iOpt.isValid( "-1" ) );

        assertFalse( "A String is not an Integer", iOpt.isValid( "eins" ) );
        assertFalse( "A String is not an Integer", iOpt.isValid( "1a" ) );
        assertFalse( "A String is not an Integer", iOpt.isValid( "a1" ) );

        assertFalse( "No floats allowed", iOpt.isValid( "1.0" ) );
        assertFalse( "No floats allowed", iOpt.isValid( "1.2" ) );

        assertFalse( "Hex not allowed", iOpt.isValid( "0x10" ) );

        assertTrue( "Leading Zeros", iOpt.isValid( "010" ) );
        iOpt.parseValue( "010" );
        assertTrue( "Octal not allowed", iOpt.getValue() == 10 );
        assertFalse( "Octal not allowed", iOpt.getValue() == 8 );
    }

    @Test
    public void optionLimitedInteger()
    {
        AbstractOptionInteger iOpt = new OptionLimitedInteger( "Limited Integer", 5, "Limited Integer Test", 1, 10 );
        assertTrue( "Legal Value", iOpt.isValid( "5" ) );
        assertTrue( "Legal Value", iOpt.isValid( "3" ) );

        assertTrue( "Test legal Limit", iOpt.isValid( "1" ) );
        assertTrue( "Test legal Limit", iOpt.isValid( "10" ) );

        assertFalse( "Test ilegal Limit", iOpt.isValid( "0" ) );
        assertFalse( "Test ilegal Limit", iOpt.isValid( "11" ) );

        assertFalse( "A String is not an Integer", iOpt.isValid( "eins" ) );
        assertFalse( "A String is not an Integer", iOpt.isValid( "1a" ) );
        assertFalse( "A String is not an Integer", iOpt.isValid( "a1" ) );

        assertFalse( "No floats allowed", iOpt.isValid( "1.0" ) );
        assertFalse( "No floats allowed", iOpt.isValid( "1.2" ) );
    }

    @Test
    public void optionVarchar()
    {
        AbstractOptionVarchar vOpt;

        vOpt = new OptionSimpleVarchar( "Varchar Option", "Value", "Varchar Option" );

        assertTrue( "Legal Value", vOpt.isValid( "Ein String" ) );

        assertFalse( "Ilegal Value", vOpt.isValid( "Ein\nZeilenumbruch" ) );

        vOpt = new OptionSimpleVarchar( "Varchar Option", "Value", "Varchar Option", 5 );

        assertTrue( "Legal Value", vOpt.isValid( "1234" ) );
        assertTrue( "Test Limit", vOpt.isValid( "12345" ) );

        assertFalse( "To long varchar", vOpt.isValid( "123456" ) );
    }
}
