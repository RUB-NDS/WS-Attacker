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
package wsattacker.plugin.intelligentdos.listener;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;

import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.Metric;

/**
 * @author Christian Altmeier
 */
public class PersistAttackListener
    implements AttackPerformedListener
{

    private static final String SEPARATOR = ", ";

    private File baseDir;

    public PersistAttackListener( String baseDirAsString )
    {
        this( new File( baseDirAsString ) );
    }

    public PersistAttackListener( File baseDir )
    {
        if ( baseDir == null )
        {
            this.baseDir = new File( System.getProperty( "java.io.tmpdir" ) );
        }
        else
        {
            this.baseDir = baseDir;
        }
    }

    @Override
    public void attackPerformed( int count, AttackModel attackModel )
    {
        File file = new File( baseDir, attackModel.getDoSAttack().getName() );
        file = new File( file, count + "_" + attackModel.getRequestType() + ".txt" );
        if ( !file.getParentFile().exists() && !file.getParentFile().mkdirs() )
        {
            return;
        }

        BufferedWriter writer = null;
        try
        {
            writer =
                new BufferedWriter( new OutputStreamWriter( new FileOutputStream( file ), Charset.defaultCharset() ) );

            for ( Metric metric : attackModel.getMetrics() )
            {
                writer.write( metric.getDuration() + SEPARATOR + metric.getContent() + "\n" );
            }

            writer.close();
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        finally
        {
            if ( writer != null )
            {
                try
                {
                    writer.close();
                }
                catch ( IOException e )
                {
                    e.printStackTrace();
                }
            }
        }

    }

}
