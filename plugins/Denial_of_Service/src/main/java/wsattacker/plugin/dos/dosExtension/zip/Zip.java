/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.zip;

import java.io.*;
import java.util.zip.*;

/**
 * @author ianyo
 */
public class Zip
{

    static final int BUFFER = 2048;

    /**
     * Reades and Zips content of folder specified by inPath and writes it to outPathFile
     * 
     * @param inPath
     * @param outPathFile
     */
    public static void createZip( String inPath, String filenameZip )
    {
        try
        {
            System.out.println( "Start generating zipfile" );

            // get a list of files from current directory
            File f = new File( inPath ); // "."
            File[] files = f.listFiles();

            // create ZipFile in current Dir
            String outPathFile = inPath + filenameZip;
            BufferedInputStream origin = null;
            FileOutputStream dest = new FileOutputStream( outPathFile );
            ZipOutputStream out = new ZipOutputStream( new BufferedOutputStream( dest ) );
            byte data[] = new byte[BUFFER];

            // add files
            for ( int i = 0; i < files.length; i++ )
            {
                // exclude Zipfile itself
                if ( !files[i].equals( filenameZip ) )
                {
                    FileInputStream fi = new FileInputStream( files[i] );
                    origin = new BufferedInputStream( fi, BUFFER );
                    ZipEntry entry = new ZipEntry( files[i].getName() );
                    out.putNextEntry( entry );
                    int count;
                    while ( ( count = origin.read( data, 0, BUFFER ) ) != -1 )
                    {
                        out.write( data, 0, count );
                    }
                    origin.close();
                }
            }
            out.close();
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }
}
