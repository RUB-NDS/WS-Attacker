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

import org.junit.Test;
import org.mockito.Mockito;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.helper.CommonParamItem;

/**
 * @author Christian Altmeier
 */
public class ThresholdStateTest
{

    @Test
    public void test()
    {
        IntelligentDoSLibraryImpl impl = Mockito.mock( IntelligentDoSLibraryImpl.class );
        AttackModel model = new AttackModel();
        when( impl.createNewTampered( false ) ).thenReturn( model );

        CommonParamItem min = new CommonParamItem( 1, 1, 1000 );
        CommonParamItem max = new CommonParamItem( 10, 10, 125 );
        ThresholdState thresholdState = new ThresholdState( min, max );
        // --> TAMPERED
        AttackModel attackModel = create( RequestType.TAMPERED, "content" );
        thresholdState.update( impl, attackModel );
        verify( impl, times( 1 ) ).createNewTampered( false );
        // <-- TAMPERED
        attackModel = create( RequestType.TAMPERED, "" );
        thresholdState.update( impl, attackModel );
        verify( impl, times( 2 ) ).createNewTampered( false );
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
