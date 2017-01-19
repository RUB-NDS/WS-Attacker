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
package wsattacker.library.intelligentdos;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import org.mockito.Mockito;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.stub;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.position.AnyElementPosition;
import wsattacker.library.intelligentdos.success.SuccessDecider;

/**
 * @author Christian Altmeier
 */
public class SuccessfulStateTest
{

    private final SuccessfulState successfulState = new SuccessfulState();

    @Test
    public void testFirstResponse()
    {
        IntelligentDoSLibraryImpl context = Mockito.mock( IntelligentDoSLibraryImpl.class );
        SuccessDecider sd = mock( SuccessDecider.class );
        when( context.getSuccessDecider() ).thenReturn( sd );
        when( sd.calculateRatio( null, new Long[0] ) ).thenReturn( 1d );
        AttackModel model = new AttackModel();

        successfulState.update( context, model );
        verify( context, times( 1 ) ).createNewTampered( false );
        verify( context, times( 1 ) ).setHasFurtherAttack( true );
    }

    @Test
    public void testSecondResponse()
    {
        IntelligentDoSLibraryImpl context = mock( IntelligentDoSLibraryImpl.class );
        SuccessDecider sd = mock( SuccessDecider.class );
        when( context.getSuccessDecider() ).thenReturn( sd );
        when( sd.calculateRatio( null, new Long[0] ) ).thenReturn( 1d );

        AttackModel model = new AttackModel();

        successfulState.update( context, model );
        successfulState.update( context, model );
        verify( context, times( 2 ) ).getSuccessDecider();
    }

    @Test
    public void testSuccessfulWithNoFurther()
    {
        IntelligentDoSLibraryImpl context = mock( IntelligentDoSLibraryImpl.class );

        SuccessDecider sd = mock( SuccessDecider.class );
        when( sd.wasSuccessful( new Long[0], new Long[0] ) ).thenReturn( true );

        when( context.getSuccessDecider() ).thenReturn( sd );

        AttackModel model = new AttackModel();
        model.setPosition( new AnyElementPosition( null, null ) );

        successfulState.update( context, model );
        successfulState.update( context, model );
        verify( context, times( 2 ) ).getSuccessDecider();

        when( context.addSuccessful( Mockito.isA( SuccessfulAttack.class ) ) ).thenReturn( true );
        verify( context ).addSuccessful( Mockito.isA( SuccessfulAttack.class ) );

        assertThat( context.hasFurtherAttack(), is( false ) );
    }

    @Test
    public void testSuccessfulWithFurther()
    {
        IntelligentDoSLibraryImpl context = mock( IntelligentDoSLibraryImpl.class );

        SuccessDecider sd = mock( SuccessDecider.class );
        when( sd.wasSuccessful( new Long[0], new Long[0] ) ).thenReturn( true );

        when( context.getSuccessDecider() ).thenReturn( sd );
        when( context.addSuccessful( Mockito.isA( SuccessfulAttack.class ) ) ).thenReturn( true );

        AttackModel attack = mock( AttackModel.class );
        DoSAttack doSAttack = mock( DoSAttack.class );
        when( attack.getDoSAttack() ).thenReturn( doSAttack );
        stub( context.createNextAttack( true ) ).toReturn( attack );

        AttackModel model = new AttackModel();
        model.setPosition( new AnyElementPosition( null, null ) );
        successfulState.update( context, model );
        successfulState.update( context, model );
        verify( context, times( 2 ) ).getSuccessDecider();

        verify( context ).addSuccessful( Mockito.isA( SuccessfulAttack.class ) );
        // the first time is on the first update
        verify( context, times( 2 ) ).setHasFurtherAttack( true );
    }

    @Test
    public void testSuccessfulWithFurtherUntampered()
    {
        IntelligentDoSLibraryImpl context = mock( IntelligentDoSLibraryImpl.class );

        SuccessDecider sd = mock( SuccessDecider.class );
        when( sd.wasSuccessful( new Long[0], new Long[0] ) ).thenReturn( true );

        when( context.getSuccessDecider() ).thenReturn( sd );
        when( context.addSuccessful( Mockito.isA( SuccessfulAttack.class ) ) ).thenReturn( true );

        AttackModel attack = mock( AttackModel.class );
        when( attack.getRequestType() ).thenReturn( RequestType.UNTAMPERED );
        when( context.createNextAttack( true ) ).thenReturn( attack );

        AttackModel model = new AttackModel();
        model.setPosition( new AnyElementPosition( null, null ) );
        successfulState.update( context, model );
        successfulState.update( context, model );
        verify( context, times( 2 ) ).getSuccessDecider();

        verify( context ).addSuccessful( Mockito.isA( SuccessfulAttack.class ) );
        // the first time is on the first update
        verify( context, times( 2 ) ).setHasFurtherAttack( true );
    }

    @Test
    public void testTestProbes()
    {
        successfulState.updateTestProbes( new Metric() );
    }

}
