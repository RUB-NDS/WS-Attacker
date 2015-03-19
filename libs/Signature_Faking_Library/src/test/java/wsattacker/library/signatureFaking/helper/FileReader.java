/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Juraj Somorovsky
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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.library.signatureFaking.helper;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.LinkedList;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class FileReader
{

    public static String[] readFileContents( final String dir )
    {
        File folder = new File( dir );
        File[] listOfFiles = folder.listFiles();
        LinkedList<String> results = new LinkedList<String>();

        for ( File cur : listOfFiles )
        {
            try
            {
                if ( cur.isFile() && !cur.isHidden() && cur.toString().endsWith( "xml" ) )
                {
                    results.add( readFile( cur.toString() ) );
                }
            }
            catch ( Exception e )
            {
                e.printStackTrace();
                System.err.println( "Could not read: " + cur.toString() );
                continue;
            }
        }
        String[] res = new String[results.size()];
        for ( int i = 0; i < results.size(); i++ )
        {
            res[i] = results.get( i );
        }
        return res;
    }

    public static String readFile( final String fileName )
        throws IOException
    {
        StringBuilder sb = new StringBuilder();

        FileInputStream fstream = new FileInputStream( fileName );
        // Get the object of DataInputStream
        DataInputStream in = new DataInputStream( fstream );
        BufferedReader br = new BufferedReader( new InputStreamReader( in ) );
        String strLine;
        // Read File Line By Line
        while ( ( strLine = br.readLine() ) != null )
        {
            // Print the content on the console
            sb.append( strLine + "\r\n" );
        }
        // Close the input stream
        in.close();
        return sb.toString();
    }
}
