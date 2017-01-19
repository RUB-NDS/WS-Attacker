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
package wsattacker.library.intelligentdos.common;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.library.intelligentdos.position.Position;

/**
 * @author Christian Altmeier
 */
public class AttackModelTest
{

    private final AttackModel attackModel = new AttackModel();

    @Test
    public void listenerTest()
    {
        PropertyChangeListener listener = mock( PropertyChangeListener.class );

        attackModel.addPropertyChangeListener( listener );

        attackModel.increase();

        verify( listener ).propertyChange( any( PropertyChangeEvent.class ) );

        attackModel.removePropertyChangeListener( listener );

        verify( listener, times( 1 ) ).propertyChange( any( PropertyChangeEvent.class ) );
    }

    @Test
    public void progressTest()
    {
        assertThat( attackModel.getProgress(), is( 0 ) );

        CommonParamItem paramItem = new CommonParamItem( 10, 1, 1000 );
        attackModel.setParamItem( paramItem );
        assertThat( attackModel.getProgress(), is( 0 ) );
        for ( int i = 0; i < 10; i++ )
        {
            attackModel.increase();
            assertThat( attackModel.getProgress(), is( ( i + 1 ) * 10 ) );
        }
    }

    @Test
    public void toStringTest()
    {

        DoSAttack doSAttack = mock( DoSAttack.class );
        when( doSAttack.getName() ).thenReturn( "lorem" );
        attackModel.setDoSAttack( doSAttack );

        Position position = mock( Position.class );
        when( position.toString() ).thenReturn( "a/b" );
        attackModel.setPosition( position );

        attackModel.setPayloadPosition( PayloadPosition.ELEMENT );
        assertThat( attackModel.toString(), is( "AttackModel[a=lorem, e=a/b, p=ELEMENT]" ) );
    }

}
