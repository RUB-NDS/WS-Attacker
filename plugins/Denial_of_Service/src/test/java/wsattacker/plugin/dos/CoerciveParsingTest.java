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
package wsattacker.plugin.dos;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author ianyo
 */
public class CoerciveParsingTest {
    private static GenericDosPluginTest t;
    private static CoerciveParsing attackPlugin;
    
    public CoerciveParsingTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
	System.out.println("Start CoerciveParsingTest");
	t = new GenericDosPluginTest();
	attackPlugin = new CoerciveParsing();	
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    @Test
    public void testInitializePlugin() {
	t.testInitializePlugin(attackPlugin);
    }    
    
    @Test
    public void testGetName() {
	t.testGetName(attackPlugin);
    }
    
    @Test
    public void testGetDescription() {
	t.testGetDescription(attackPlugin);
    }
    
    @Test
    public void testGetCountermeasures() {
	t.testGetCountermeasures(attackPlugin);
    }    
    
    @Test
    public void testGetAuthor() {
	t.testGetAuthor(attackPlugin);
    }        
    
    @Test
    public void testGetVersion() {
	t.testGetVersion(attackPlugin);
    }     
    
    @Test
    public void testCreateTamperedRequest() {
	t.testCreateTamperedRequest(attackPlugin);
    }           
}
