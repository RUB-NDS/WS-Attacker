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
package wsattacker.plugin.dos.dosExtension.attackClasses.hashDos;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ianyo
 */
public class CollisionDJBX31ATest {

    public CollisionDJBX31ATest() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getHash method, of class CollisionDJBX31A.
     */
    @Test
    public void testGetHash() {
	System.out.println("Test getHash-DJBX31A");
	String s = "EzFY";
	CollisionDJBX31A instance = new CollisionDJBX31A();
	int expResult = 2175080;
	int result = instance.getHash(s);
	assertEquals(expResult, result);
    }

    @Test
    public void testCollisionsFail() {
	CollisionDJBX31A instance = new CollisionDJBX31A();

	// Alle 4 erzeugen anderes Ergebnis, es gilt Ez <> FY
	System.out.println("Test collision Fail-DJBX31A");
	int t1 = instance.getHash("Ez");
	int t2 = instance.getHash("Fy");
	int t3 = instance.getHash("EzEz");
	int t4 = instance.getHash("EzFY");
	int t5 = instance.getHash("FYEz");
	int t6 = instance.getHash("FYFY");

	if (t1 != t2 && t2 != t3 && t3 != t4 && t4 != t5 && t5 != t6) {
	    assertTrue(true);
	}else{
	    assertTrue(false);
	}
    }

    @Test
    public void testCollisionsOk() {
	CollisionDJBX31A instance = new CollisionDJBX31A();

	System.out.println("Test collision OK-DJBX31A");
	int t1 = instance.getHash("tttt");
	int t2 = instance.getHash("ttuU");
	int t3 = instance.getHash("ttv6");
	int t4 = instance.getHash("uUtt");
	int t5 = instance.getHash("uUuU");
	int t6 = instance.getHash("uUv6");
	int t7 = instance.getHash("v6tt");
	int t8 = instance.getHash("v6uU");
	int t9 = instance.getHash("v6v6");

	if (t1 == t2 && t2 == t3 && t3 == t4 && t4 == t5 && t5 == t6 && t6 == t7 && t7 == t8 && t8 == t9) {
	    assertTrue(true);
	}else{
	    assertTrue(false);
	}
    }

    /**
     * Test of gen3nCollisions method, of class CollisionDJBX31A.
     */
    @Test
    public void testGenNCollisions() {
	System.out.println("Test genNCollisions-DJBX31A");
	int numberAttributes = 32;
	StringBuilder sb = new StringBuilder();
	CollisionDJBX31A instance = new CollisionDJBX31A();
	instance.genNCollisions(numberAttributes, sb, false);

	// We got here so no everthing OK
	if (sb.toString().length() > 0) {
	    assertTrue(true);
	}else{
	    assertTrue(false);
	}
    }

    /**
     * Test of getCollisionString method, of class CollisionDJBX31A.
     */
    @Test
    public void testGetCollisionString() {
	System.out.println("Test getCollisionString-DJBX31A");
	int i = 9 - 1;
	int n = 2;
	CollisionDJBX31A instance = new CollisionDJBX31A();
	String expResult = "v6v6";
	String result = instance.getCollisionString(i, n);
	assertEquals(expResult, result);
    }
}
