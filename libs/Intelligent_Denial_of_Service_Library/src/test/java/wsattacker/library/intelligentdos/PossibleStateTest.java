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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.mockito.Mockito;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.dos.DoSAttack;

/**
 * @author Christian Altmeier
 */
public class PossibleStateTest
{

    private final PossibleState notPossibleState = new PossibleState();

    @Test
    public void notPossibleTest()
    {
        IntelligentDoSLibraryImpl impl = Mockito.mock( IntelligentDoSLibraryImpl.class );

        // --> TAMPERED
        AttackModel attackModel = create( RequestType.TAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewUntampered( true );
        // <-- UNTAMPERED
        attackModel = create( RequestType.UNTAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).setDoSState( org.mockito.Matchers.any( FinishState.class ) );
    }

    @Test
    public void soapFaultTest()
    {
        IntelligentDoSLibraryImpl impl = Mockito.mock( IntelligentDoSLibraryImpl.class );

        // --> TAMPERED
        AttackModel attackModel = create( RequestType.TAMPERED, "Fault>" );
        DoSAttack doSAttack = mock( DoSAttack.class );
        attackModel.setDoSAttack( doSAttack );
        notPossibleState.update( impl, attackModel );

        verify( impl, times( 1 ) ).createNewUntampered( null );
        // <-- UNTAMPERED
        attackModel = create( RequestType.UNTAMPERED, "Fault>" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).setDoSState( org.mockito.Matchers.any( FinishState.class ) );
    }

    @Test
    public void revalidateOkTest()
    {
        IntelligentDoSLibraryImpl impl = Mockito.mock( IntelligentDoSLibraryImpl.class );

        // --> TAMPERED
        AttackModel attackModel = create( RequestType.TAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewUntampered( true );
        // <-- UNTAMPERED

        // --> UNTAMPERED
        attackModel = create( RequestType.UNTAMPERED, "content" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewTampered( true );
        // <-- TAMPERED

        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "content" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 2 ) ).createNewTampered( true );
        // <-- Tampered
        // --> Tampered
        attackModel = create( RequestType.TAMPERED, "content" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).setDoSState( org.mockito.Matchers.any( TamperedState.class ) );
    }

    @Test
    public void minimalParamTest()
    {
        IntelligentDoSLibraryImpl impl = Mockito.mock( IntelligentDoSLibraryImpl.class );
        AttackModel value = new AttackModel();
        when( impl.createNewTampered( false ) ).thenReturn( value );

        // --> TAMPERED
        AttackModel attackModel = create( RequestType.TAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewUntampered( true );
        // <-- UNTAMPERED

        // --> UNTAMPERED
        attackModel = create( RequestType.UNTAMPERED, "content" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewTampered( true );
        // <-- TAMPERED

        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).createNewTampered( false );
        verify( impl ).createNewTampered( true );
        assertThat( value.getParamItem().getNumberOfRequests(), is( 1 ) );
        assertThat( value.getParamItem().getNumberOfThreads(), is( 1 ) );
        assertThat( value.getParamItem().getMilliesBetweenRequests(), is( 1000 ) );
        // <-- TAMPERED

        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "content" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).setDoSState( org.mockito.Matchers.any( ThresholdState.class ) );
    }

    @Test
    public void attackNotPossibleTest()
    {
        IntelligentDoSLibraryImpl impl = Mockito.mock( IntelligentDoSLibraryImpl.class );
        AttackModel value = new AttackModel();
        when( impl.createNewTampered( false ) ).thenReturn( value );
        when( impl.getCurrentAttack() ).thenReturn( value );

        DoSAttack doSAttack = mock( DoSAttack.class );

        // --> TAMPERED
        AttackModel attackModel = create( RequestType.TAMPERED, "" );
        attackModel.setDoSAttack( doSAttack );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewUntampered( true );
        // <-- UNTAMPERED

        // --> UNTAMPERED
        attackModel = create( RequestType.UNTAMPERED, "content" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewTampered( true );
        // <-- TAMPERED

        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewTampered( false );
        verify( impl, times( 1 ) ).createNewTampered( true );
        assertThat( value.getParamItem().getNumberOfRequests(), is( 1 ) );
        assertThat( value.getParamItem().getNumberOfThreads(), is( 1 ) );
        assertThat( value.getParamItem().getMilliesBetweenRequests(), is( 1000 ) );
        // <-- TAMPERED

        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).createNewTampered( org.mockito.Matchers.any( DoSAttack.class ) );
        // <-- TAMPERED
        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "" );
        value.setRequestType( RequestType.UNTAMPERED );
        notPossibleState.update( impl, attackModel );
        verify( impl ).addNotPossible( org.mockito.Matchers.any( DoSAttack.class ) );
        verify( impl ).setDoSState( org.mockito.Matchers.any( UntamperedState.class ) );
    }

    @Test
    public void attackPossibleTest()
    {
        IntelligentDoSLibraryImpl impl = Mockito.mock( IntelligentDoSLibraryImpl.class );
        AttackModel value = new AttackModel();
        when( impl.createNewTampered( false ) ).thenReturn( value );
        when( impl.getCurrentAttack() ).thenReturn( value );

        DoSAttack doSAttack = mock( DoSAttack.class );

        // --> TAMPERED
        AttackModel attackModel = create( RequestType.TAMPERED, "" );
        attackModel.setDoSAttack( doSAttack );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewUntampered( true );
        // <-- UNTAMPERED

        // --> UNTAMPERED
        attackModel = create( RequestType.UNTAMPERED, "content" );
        notPossibleState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewTampered( true );
        // <-- TAMPERED

        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).createNewTampered( false );
        verify( impl ).createNewTampered( true );
        assertThat( value.getParamItem().getNumberOfRequests(), is( 1 ) );
        assertThat( value.getParamItem().getNumberOfThreads(), is( 1 ) );
        assertThat( value.getParamItem().getMilliesBetweenRequests(), is( 1000 ) );
        // <-- TAMPERED

        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).createNewTampered( org.mockito.Matchers.any( DoSAttack.class ) );
        // <-- TAMPERED (minimal DoS)
        // --> TAMPERED
        attackModel = create( RequestType.TAMPERED, "content" );
        notPossibleState.update( impl, attackModel );
        verify( impl ).setDoSState( org.mockito.Matchers.any( ThresholdState.class ) );
    }

    private AttackModel create( RequestType requestType, String content )
    {
        AttackModel attackModel = new AttackModel();
        for ( int i = 0; i < 10; i++ )
        {
            Metric metric = new Metric();
            metric.setContent( content );
            metric.setDuration( 1000 );
            attackModel.addMetric( metric );

            attackModel.setRequestType( requestType );
        }
        return attackModel;
    }

}
