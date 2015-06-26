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
package wsattacker.library.intelligentdos.hashdos;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.util.Set;

import org.junit.Test;

/**
 * @author Christian Altmeier
 */
public class CollisionDJBXTest
{

    CollisionDJBX collisionDJBX = new CollisionDJBX();

    @Test
    public void test()
    {
        assertThat( collisionDJBX.getHash( "0" ), is( 49 ) );
        assertThat( collisionDJBX.getHash( "9" ), is( 58 ) );
        assertThat( collisionDJBX.getHash( "A" ), is( 67 ) );
        assertThat( collisionDJBX.getHash( "Z" ), is( 92 ) );
        assertThat( collisionDJBX.getHash( "a" ), is( 100 ) );
        assertThat( collisionDJBX.getHash( "z" ), is( 125 ) );

        assertThat( collisionDJBX.getHash( "aa" ), is( 6562050 ) );
        assertThat( collisionDJBX.getHash( "bb" ), is( 6629700 ) );

        assertThat( collisionDJBX.getHash( "AA" ), is( 4397250 ) );

        assertThat( collisionDJBX.getHash( "000" ), is( 412191697 ) );
        assertThat( collisionDJBX.getHash( "009" ), is( 412191706 ) );
        assertThat( collisionDJBX.getHash( "00A" ), is( 412191715 ) );
        assertThat( collisionDJBX.getHash( "00Z" ), is( 412191740 ) );
        assertThat( collisionDJBX.getHash( "00a" ), is( 412191748 ) );

        assertThat( collisionDJBX.getHash( "900" ), is( 488868790 ) );
        assertThat( collisionDJBX.getHash( "Z00" ), is( 770018132 ) );
        assertThat( collisionDJBX.getHash( "zzz" ), is( 1047653897 ) );

        assertThat( collisionDJBX.getHash( "0000" ), is( -811407168 ) );
        assertThat( collisionDJBX.getHash( "0zzz" ), is( -175944968 ) );
        assertThat( collisionDJBX.getHash( "2PUz" ), is( 1073686683 ) );
    }

    @Test
    public void complexTest()
    {
        assertThat( collisionDJBX.getHash( "2PV0" ), is( 1073754255 ) );
        assertThat( collisionDJBX.getHash( "test" ), is( 1233125307 ) );
        assertThat( collisionDJBX.getHash( "waddehaddedudeda" ), is( -671098362 ) );
    }

    @Test
    public void hashForthTest()
    {
        assertThat( collisionDJBX.hashForth( "0" ), is( 48 ) );
        assertThat( collisionDJBX.hashForth( "abc" ), is( 807794786 ) );
    }

    @Test
    public void hashBackTest()
    {
        assertThat( collisionDJBX.hashBack( "0", 7 ), is( 776968809 ) );
        assertThat( collisionDJBX.hashBack( "abc", 7 ), is( 118185115 ) );
    }

    @Test
    public void hashForthBackTest()
    {
        assertThat( collisionDJBX.hashForth( "abc" ), is( 807794786 ) );
        assertThat( collisionDJBX.hashBack( "abc", 807794786 ), is( 0 ) );
    }

    @Test
    public void genNCollisionsTest()
    {
        StringBuilder sb = new StringBuilder();
        collisionDJBX.genNCollisions( 2, sb, false );
        assertThat( sb.toString(), is( "qqSD2u3H1h=\"qqSD2u3H1h\" DhOXtEllgi=\"DhOXtEllgi\" " ) );

        sb = new StringBuilder();
        collisionDJBX.genNCollisions( 2, sb, true );
        assertThat( sb.toString(), is( "xmlns:qqSD2u3H1h=\"qqSD2u3H1h\" xmlns:DhOXtEllgi=\"DhOXtEllgi\" " ) );
    }

    @Test
    public void generationTest()
    {
        collisionDJBX.setLengthString( 6 );
        collisionDJBX.setLengthSuffix( 3 );
        Set<String> generateCollionsMeetInTheMiddle = collisionDJBX.generateCollionsMeetInTheMiddle( 10 );
        for ( String string : generateCollionsMeetInTheMiddle )
        {
            assertThat( collisionDJBX.getHash( string ), is( 0 ) );
        }
    }

}
