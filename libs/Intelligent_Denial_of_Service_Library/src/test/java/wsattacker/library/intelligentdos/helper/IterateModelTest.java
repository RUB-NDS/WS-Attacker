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
package wsattacker.library.intelligentdos.helper;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.util.NoSuchElementException;

import org.junit.Test;

import wsattacker.library.intelligentdos.helper.IterateModel.IncreaseIncrementStrategie;
import wsattacker.library.intelligentdos.helper.IterateModel.IterateStrategie;

public class IterateModelTest
{

    @Test
    public void initial()
    {
        IterateModel iterateModel = IterateModel.custom().build();
        assertThat( iterateModel.getStartAt(), is( 0 ) );
        assertThat( iterateModel.getStopAt(), is( Integer.MAX_VALUE ) );
        assertThat( iterateModel.getIncrement(), is( 1 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
    }

    @Test
    public void simpleNext()
    {
        IterateModel iterateModel = IterateModel.custom().build();
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 0 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 1 ) );
    }

    @Test
    public void incrementTwoAdd()
    {
        IterateModel iterateModel = IterateModel.custom().setIncrement( 2 ).build();
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 0 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 2 ) );
    }

    @Test
    public void incrementTwoAddWithStop()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 8 ).setIncrement( 2 ).build();
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 2 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 4 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 6 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 8 ) );
        assertThat( iterateModel.hasNext(), is( false ) );
    }

    @Test
    public void incrementTwoPow()
    {
        IterateModel iterateModel =
            IterateModel.custom().startAt( 2 ).setIncrement( 2 ).setIterateStrategie( IterateStrategie.MUL ).build();
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 2 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 4 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 8 ) );
    }

    @Test
    public void incrementMulWithFor()
    {
        IterateModel iterModel =
            IterateModel.custom().startAt( 512 ).stopAt( 16384 ).setIncrement( 2 ).setIterateStrategie( IterateStrategie.MUL ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.NO ).build();
        int count = 0;
        int[] values = { 512, 1024, 2048, 4096, 8192, 16384 };
        for ( int value = iterModel.getStartAt(); value < iterModel.getStopAt(); value = iterModel.increment( value ) )
        {
            assertThat( value, is( values[count] ) );
            count++;
        }

        assertThat( count, is( 5 ) );
    }

    @Test
    public void incrementTwoSub()
    {
        IterateModel iterateModel =
            IterateModel.custom().startAt( 8 ).stopAt( 0 ).setIncrement( 2 ).setIterateStrategie( IterateStrategie.SUB ).build();
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 8 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 6 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 4 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 2 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 0 ) );
        assertThat( iterateModel.hasNext(), is( false ) );
    }

    @Test
    public void increaseNo()
    {
        IterateModel iterateModel =
            IterateModel.custom().startAt( 8 ).stopAt( 32 ).setIncrement( 2 ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.NO ).build();
        iterateModel.increaseIncrement();
        iterateModel.increaseIncrement();
        assertThat( iterateModel.getIncrement(), is( 2 ) );
    }

    @Test
    public void increaseAgressive()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 8 ).stopAt( 32 ).setIncrement( 2 ).build();
        iterateModel.increaseIncrement(); // -> 2 * 2 = 4
        iterateModel.increaseIncrement(); // -> 4 * 2,5 =10
        iterateModel.increaseIncrement(); // -> 10 * 3 = 30
        assertThat( iterateModel.getIncrement(), is( 30 ) );
    }

    @Test
    public void increaseModerate()
    {
        IterateModel iterateModel =
            IterateModel.custom().startAt( 8 ).stopAt( 32 ).setIncrement( 4 ).setIncreaseIncrementStrategie( IncreaseIncrementStrategie.MODERATE ).build();
        iterateModel.increaseIncrement(); // -> 4 * 1,25 = 5
        iterateModel.increaseIncrement(); // -> 5 * 1,5 = 7
        iterateModel.increaseIncrement(); // -> 7 * 1,75 = 12
        assertThat( iterateModel.getIncrement(), is( 12 ) );
    }

    @Test
    public void stopAfter()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 10 ).stopAt( 11 ).build();

        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 10 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 11 ) );
        assertThat( iterateModel.hasNext(), is( false ) );
    }

    @Test
    public void reset()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 10 ).stopAt( 11 ).build();

        for ( int i = 0; i < 2; i++ )
        {
            assertThat( iterateModel.hasNext(), is( true ) );
            assertThat( iterateModel.next(), is( 10 ) );
            assertThat( iterateModel.hasNext(), is( true ) );
            assertThat( iterateModel.next(), is( 11 ) );
            assertThat( iterateModel.hasNext(), is( false ) );
            iterateModel.reset();
        }
    }

    @Test
    public void resetAfterIncrease()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 2 ).stopAt( 16 ).setIncrement( 2 ).build();

        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 2 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 4 ) );
        assertThat( iterateModel.hasNext(), is( true ) );

        iterateModel.increaseIncrement();

        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 8 ) );

        iterateModel.reset();

        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 2 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 4 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
    }

    @Test( expected = NoSuchElementException.class )
    public void test()
    {
        IterateModel iterateModel = IterateModel.custom().startAt( 1 ).stopAt( 2 ).build();
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 1 ) );
        assertThat( iterateModel.hasNext(), is( true ) );
        assertThat( iterateModel.next(), is( 2 ) );
        assertThat( iterateModel.hasNext(), is( false ) );
        // should throw an exception
        iterateModel.next();
    }

}
