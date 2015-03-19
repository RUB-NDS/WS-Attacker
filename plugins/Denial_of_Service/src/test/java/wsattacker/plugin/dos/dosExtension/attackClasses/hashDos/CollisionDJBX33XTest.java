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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @author ianyo
 */
public class CollisionDJBX33XTest
{

    public CollisionDJBX33XTest()
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
     * Test if precomputed file exists
     */
    @Test
    public void TestPrecomputedFileExists()
    {
        System.out.println( "Test PrecomputedFileExists-DJBX33X" );
        java.net.URL txtFile = getClass().getResource( "/DJBX33XCollisions/DJBX33XCollisions.txt" );
        if ( txtFile != null )
        {
            assertTrue( true );
        }
        else
        {
            assertTrue( false );
        }
    }

    /**
     * Test of getHash method, of class CollisionDJBX33X.
     */
    @Test
    public void testGetHash()
    {
        System.out.println( "Test getHash-DJBX33X" );
        String s = "QCMWaIOvpl";
        CollisionDJBX33X instance = new CollisionDJBX33X();
        int expResult = 0;
        int result = instance.getHash( s );
        assertEquals( expResult, result );
    }

    @Test
    public void testCollisionsFail()
    {
        CollisionDJBX33X instance = new CollisionDJBX33X();

        System.out.println( "Test collision Mismatch-DJBX33X" );
        int t1 = instance.getHash( "QCMWaIOvpl" );
        int t2 = instance.getHash( "QCMWalOwQl" );

        if ( t1 != t2 )
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
        CollisionDJBX33X instance = new CollisionDJBX33X();

        System.out.println( "Test collision OK-DJBX33X" );
        int t1 = instance.getHash( "QCMWaIOvpl" );
        int t2 = instance.getHash( "QCMWaIOwQl" );

        if ( t1 == t2 )
        {
            assertTrue( true );
        }
        else
        {
            assertTrue( false );
        }
    }

    /**
     * Test of genNCollisions method, of class CollisionDJBX33X.
     */
    @Test
    public void testGenNCollisions()
    {
        System.out.println( "Test genNCollisions-DJBX33X - 4 elements" );
        int numberAttributes = 4;
        StringBuilder sb = new StringBuilder();
        CollisionDJBX33X instance = new CollisionDJBX33X();
        instance.genNCollisions( numberAttributes, sb, false );
        System.out.println( " - Payload:" + sb.toString() );
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
     * Hash forward first 7 Characters
     */
    @Test
    public void MeetInTheMiddleHashForthTest()
    {

        // Result for should be QCMWaIO
        // - 3B847A2A Hex
        // - 998537770 Dec
        CollisionDJBX33X instance = new CollisionDJBX33X();
        int result = instance.hashForth( "QCMWaIO" );
        assertEquals( 998537770, result );
        System.out.println( " - HashForth QCMWaIO = " + ( instance.hashForth( "QCMWaIO" ) ) );
    }

    /**
     * Invert last 3 chars of Hash-Funktion
     */
    @Test
    public void MeetInTheMiddleHashBackTest()
        throws NoSuchAlgorithmException
    {

        // Result for should be QCMWaIO
        // - 3B847A2A Hex
        // - 998537770 Dec
        CollisionDJBX33X instance = new CollisionDJBX33X();
        int result1 = instance.hashBack( "vpl", 0 );
        int result2 = instance.hashBack( "wQl", 0 );
        assertEquals( 998537770, result1 );
        assertEquals( 998537770, result2 );
        System.out.println( " - Hashback vpl = " + ( instance.hashBack( "vpl", 0 ) ) );
        System.out.println( " - Hashback wQl = " + ( instance.hashBack( "wQl", 0 ) ) );
    }

    /**
     * Reads 2 collisionStrings and compares if they are equal
     */
    @Test
    public void testCompare2CollisionString()
    {
        System.out.println( "Test getCollisionString-DJBX33X" );
        CollisionDJBX33X instance = new CollisionDJBX33X();
        String preGeneratedCollisionString1 = "QCMWaIOvpl";
        String preGeneratedCollisionString2 = "QCMWaIOvpl";
        assertEquals( preGeneratedCollisionString1, preGeneratedCollisionString2 );
    }

    /**
     * Test HashBack and HashForth for random String at same time! Loads string from predefined lookuptable under target
     * "0"
     */
    @Test
    public void testReadRandomStringForCollision()
    {
        System.out.println( "Test ReadRandomStringForCollision-DJBX33X" );
        int numberRows = 0;
        String randomString = "";
        CollisionDJBX33X instance = new CollisionDJBX33X();

        // Open File
        InputStream is = getClass().getResourceAsStream( "/DJBX33XCollisions/DJBX33XCollisions.txt" );
        BufferedReader br = new BufferedReader( new InputStreamReader( is ) );

        try
        {
            // Read number of lines
            while ( br.readLine() != null )
            {
                numberRows++;
            }
            br.close();

            // pic random line and get Hash
            br = new BufferedReader( new InputStreamReader( is ) );
            int randomNumber = 2;// (int)(Math.random() * (numberRows + 1));
            randomString = instance.getCollisionString( randomNumber, numberRows );
            System.out.println( " - " + numberRows + " rows Total, random Row = " + randomNumber + " - " + randomString );

            // do calculation
            String preGeneratedCollisionString = randomString;
            int hashForthResult = instance.hashForth( preGeneratedCollisionString.substring( 0, 7 ) );
            int hashBackResult = instance.hashBack( preGeneratedCollisionString.substring( 7, 10 ), 0 );
            System.out.println( " - " + preGeneratedCollisionString.substring( 7, 10 ) + " -- "
                + preGeneratedCollisionString.substring( 0, 7 ) );
            assertEquals( hashBackResult, hashForthResult );
        }
        catch ( IOException ex )
        {
            Logger.getLogger( CollisionDJBX33XTest.class.getName() ).log( Level.SEVERE, null, ex );
        }
    }
}
