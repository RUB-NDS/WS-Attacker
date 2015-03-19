/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
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
package wsattacker.library.signatureWrapping.util.id;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * @author christian
 */
public class RandomIdGeneratorTest
{

    @Test
    public void testRotate_ID()
    {
        String originalID, generatedID;

        originalID = "abcmnxyz";
        for ( int i = 0; i < 100; ++i )
        {
            generatedID = RandomIdGenerator.rotate_ID( originalID );
            assertEquals( originalID.length(), generatedID.length() );
            assertTrue( String.format( "Error: '%s' ==> '%s'", originalID, generatedID ),
                        generatedID.matches( "[a-z]{8}" ) );
            assertFalse( String.format( "Error: Strings are equal '%s'", originalID ), originalID.equals( generatedID ) );
        }

        originalID = "ABCMNXYZ";
        for ( int i = 0; i < 100; ++i )
        {
            generatedID = RandomIdGenerator.rotate_ID( originalID );
            assertEquals( originalID.length(), generatedID.length() );
            assertTrue( String.format( "Error: '%s' ==> '%s'", originalID, generatedID ),
                        generatedID.matches( "[A-Z]{8}" ) );
            assertFalse( String.format( "Error: Strings are equal '%s'", originalID ), originalID.equals( generatedID ) );
        }

        originalID = "0123456789";
        for ( int i = 0; i < 100; ++i )
        {
            generatedID = RandomIdGenerator.rotate_ID( originalID );
            assertEquals( originalID.length(), generatedID.length() );
            assertTrue( String.format( "Error: '%s' ==> '%s'", originalID, generatedID ),
                        generatedID.matches( "[0-9]{10}" ) );
            assertFalse( String.format( "Error: Strings are equal '%s'", originalID ), originalID.equals( generatedID ) );
        }

        originalID = "_ab-12.XY";
        for ( int i = 0; i < 100; ++i )
        {
            generatedID = RandomIdGenerator.rotate_ID( originalID );
            assertEquals( originalID.length(), generatedID.length() );
            assertTrue( String.format( "Error: '%s' ==> '%s'", originalID, generatedID ),
                        generatedID.matches( "_[a-z]{2}-[0-9]{2}.[A-Z]{2}" ) );
            assertFalse( String.format( "Error: Strings are equal '%s'", originalID ), originalID.equals( generatedID ) );
        }
    }
}
