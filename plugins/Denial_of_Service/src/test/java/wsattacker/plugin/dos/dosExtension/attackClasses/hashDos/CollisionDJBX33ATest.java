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
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author ianyo
 */
public class CollisionDJBX33ATest
{

    public CollisionDJBX33ATest()
    {
    }

    @Before
    public void setUp()
    {
    }

    @After
    public void tearDown()
    {
    }

    /**
     * Test of getHash method, of class CollisionDJBX33A.
     */
    @Test
    public void testGetHash()
    {
        String s = "AzC8";
        CollisionDJBX33A instance = new CollisionDJBX33A();
        int expResult = 2088944635;
        int result = instance.getHash( s );
        assertEquals( expResult, result );
    }

    @Test
    public void testCollisionsFail()
    {
        CollisionDJBX33A instance = new CollisionDJBX33A();
        // Alle 4 erzeugen anderes Ergebnis, es gilt Ez <> FY

        int t1 = instance.getHash( "AB" );
        int t2 = instance.getHash( "Cd" );
        int t3 = instance.getHash( "ABAB" );
        int t4 = instance.getHash( "ABCd" );
        int t5 = instance.getHash( "CdAB" );
        int t6 = instance.getHash( "CdCd" );

        if ( t1 != t2 && t2 != t3 && t3 != t4 && t4 != t5 && t5 != t6 )
        {
            assertTrue( true );
        }
        else
        {
            assertTrue( false );
        }
    }

    @Test
    public void testCollisionsOk()
    {
        CollisionDJBX33A instance = new CollisionDJBX33A();

        int t1 = instance.getHash( "Az" );
        int t2 = instance.getHash( "C8" );
        int t3 = instance.getHash( "AzAz" );
        int t4 = instance.getHash( "AzC8" );
        int t5 = instance.getHash( "C8Az" );
        int t6 = instance.getHash( "C8C8" );

        if ( t1 == t2 && t3 == t4 && t4 == t5 && t5 == t6 )
        {
            assertTrue( true );
        }
        else
        {
            assertTrue( false );
        }
    }

    /**
     * Test of genNCollisions method, of class CollisionDJBX33A.
     */
    @Test
    public void testGenNCollisions()
    {
        System.out.println( "Test genNCollisions-DJBX33A" );
        int numberAttributes = 32;
        StringBuilder sb = new StringBuilder();
        CollisionDJBX33A instance = new CollisionDJBX33A();
        instance.genNCollisions( numberAttributes, sb, false );
        // We got here so no everthing OK
        if ( sb.toString().length() > 0 )
        {
            assertTrue( true );
        }
        else
        {
            assertTrue( false );
        }
    }

    /**
     * Test of getCollisionString method, of class CollisionDJBX33A.
     */
    @Test
    public void testGetCollisionString()
    {
        System.out.println( "Test getCollisionString-DJBX33A" );
        int i = 4 - 1;
        int n = 2;
        CollisionDJBX33A instance = new CollisionDJBX33A();
        String expResult = "C8C8";
        String result = instance.getCollisionString( i, n );
        assertEquals( expResult, result );
    }

}
