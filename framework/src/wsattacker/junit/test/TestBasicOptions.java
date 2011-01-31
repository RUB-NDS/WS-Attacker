/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010  Christian Mainka
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package wsattacker.junit.test;

import org.junit.Test;
import static org.junit.Assert.*;

import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;
import wsattacker.main.plugin.option.OptionLimitedInteger;
import wsattacker.main.plugin.option.OptionSimpleInteger;
import wsattacker.main.plugin.option.OptionSimpleVarchar;

public class TestBasicOptions {

	@Test
	public void optionInteger() {
		AbstractOptionInteger iOpt = new OptionSimpleInteger("Integer", 0, "Integer Test");
		assertTrue("Legal Value", iOpt.parseValue("0"));
		assertTrue("Legal Value", iOpt.parseValue("1"));
		assertTrue("Legal Value", iOpt.parseValue("9999"));
		assertTrue("Legal Value", iOpt.parseValue("-1"));
		
		assertFalse("A String is not an Integer", iOpt.parseValue("eins"));
		assertFalse("A String is not an Integer", iOpt.parseValue("1a"));
		assertFalse("A String is not an Integer", iOpt.parseValue("a1"));
		
		assertFalse("No floats allowed", iOpt.parseValue("1.0"));
		assertFalse("No floats allowed", iOpt.parseValue("1.2"));
		
		assertFalse("Hex not allowed", iOpt.parseValue("0x10"));
		
		assertTrue("Leading Zeros", iOpt.parseValue("010"));
		assertTrue("Octal not allowed", iOpt.getValue() == 10);
		assertFalse("Octal not allowed", iOpt.getValue() == 8);
	}
	
	@Test
	public void optionLimitedInteger() {
		AbstractOptionInteger iOpt = new OptionLimitedInteger("Limited Integer", 5, "Limited Integer Test", 1, 10);
		assertTrue("Legal Value", iOpt.parseValue("5"));
		assertTrue("Legal Value", iOpt.parseValue("3"));
		
		assertTrue("Test legal Limit", iOpt.parseValue("1"));
		assertTrue("Test legal Limit", iOpt.parseValue("10"));
		
		assertFalse("Test ilegal Limit", iOpt.parseValue("0"));
		assertFalse("Test ilegal Limit", iOpt.parseValue("11"));
		
		assertFalse("A String is not an Integer", iOpt.parseValue("eins"));
		assertFalse("A String is not an Integer", iOpt.parseValue("1a"));
		assertFalse("A String is not an Integer", iOpt.parseValue("a1"));
		
		assertFalse("No floats allowed", iOpt.parseValue("1.0"));
		assertFalse("No floats allowed", iOpt.parseValue("1.2"));
	}
	
	@Test
	public void optionVarchar() {
		AbstractOptionVarchar vOpt;
		
		vOpt = new OptionSimpleVarchar("Varchar Option","Value","Varchar Option");
		
		assertTrue("Legal Value", vOpt.parseValue("Ein String"));
		
		assertFalse("Ilegal Value", vOpt.parseValue("Ein\nZeilenumbruch"));
		

		vOpt = new OptionSimpleVarchar("Varchar Option","Value","Varchar Option",5);
		
		assertTrue("Legal Value", vOpt.parseValue("1234"));
		assertTrue("Test Limit", vOpt.parseValue("12345"));
		
		assertFalse("To long varchar", vOpt.parseValue("123456"));
	}
}
