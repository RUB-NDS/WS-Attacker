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
package wsattacker.testhelper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;

/**
 * @author Christian Altmeier
 */
public class RecordedMetricOracle
    implements MetricOracle
{

    private List<File> list;

    private int index = 0;

    public RecordedMetricOracle( File folder )
    {
        @SuppressWarnings( "unchecked" )
        Collection<File> listFiles = FileUtils.listFiles( folder, new String[] { "txt" }, true );

        list = new ArrayList<File>( listFiles );
        Collections.sort( list, new Comparator<File>()
        {

            @Override
            public int compare( File o1, File o2 )
            {
                String o1name = o1.getName();
                String o2name = o2.getName();
                String o1indexString = o1name.substring( 0, o1name.indexOf( "_" ) );
                String o2indexString = o2name.substring( 0, o2name.indexOf( "_" ) );

                Integer o1index = Integer.valueOf( o1indexString );
                Integer o2index = Integer.valueOf( o2indexString );

                return o1index - o2index;
            }
        } );
    }

    @Override
    public void createMetric( AttackModel attackModel )
    {
        File file = list.get( index );

        BufferedReader reader = null;
        try
        {
            reader = new BufferedReader( new FileReader( file ) );
            String data = null;
            while ( ( data = reader.readLine() ) != null )
            {
                int indexOf = data.indexOf( ", " );
                Long duration = Long.valueOf( data.substring( 0, indexOf ) );

                Metric metric = new Metric();
                metric.setDuration( duration );
                metric.setContent( StringUtils.trimToEmpty( data.substring( indexOf + 2 ) ) );
                attackModel.addMetric( metric );
            }
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        finally
        {
            if ( reader != null )
            {
                try
                {
                    reader.close();
                }
                catch ( IOException e )
                {
                    // ignore
                }
            }
        }

        index++;
    }

}
