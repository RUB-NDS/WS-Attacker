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
package wsattacker.plugin.intelligentdos.model;

import com.google.common.collect.Lists;
import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.common.Threshold;
import wsattacker.plugin.intelligentdos.persistence.ResultDoSAttack;

/**
 * @author Christian Altmeier
 */
public class ResultModelTest
{

    @Test
    public void persistenceTest()
        throws IOException
    {
        File createTempFile = File.createTempFile( "test", ".zip" );
        createTempFile.deleteOnExit();

        Date startDate = new Date();
        Date stopDate = new Date();
        String name = "Lorem Ipsum 1";
        String name2 = "Lorem Ipsum 2";

        ResultModel model = new ResultModel();
        model.setStartDate( startDate );
        model.setStopDate( stopDate );

        model.getNotPossible().add( createDoSAttack( name ) );
        model.getNotPossible().add( createDoSAttack( name2 ) );

        Threshold threshold = new Threshold( createDoSAttack( name ), createDoSAttack( name2 ) );
        model.getThresholds().add( threshold );

        model.save( createTempFile );

        ResultModel model2 = new ResultModel();
        model2.readIn( createTempFile );

        Date startDate2 = model2.getStartDate();
        Date stopDate2 = model2.getStopDate();

        assertTrue( startDate.equals( startDate2 ) );
        assertTrue( stopDate.equals( stopDate2 ) );

        assertThat( model2.getNotPossible().size(), is( 2 ) );
        assertThat( model2.getNotPossible().get( 0 ).getName(), is( name ) );
        assertThat( model2.getNotPossible().get( 1 ).getName(), is( name2 ) );

        assertThat( model2.getThresholds().size(), is( 1 ) );
        assertThat( model2.getThresholds().get( 0 ).getMinimum().getName(), is( name ) );
        assertThat( model2.getThresholds().get( 0 ).getMaximum().getName(), is( name2 ) );
    }

    private ResultDoSAttack createDoSAttack( String name )
    {
        List<DoSParam<?>> list = Lists.newArrayList();
        list.add( new DoSParam<String>( "description", "value" ) );
        ResultDoSAttack e = new ResultDoSAttack( list );

        e.setName( name );
        return e;
    }

}
